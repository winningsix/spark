package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}
import org.apache.spark.sql.execution.datasources.parquet.ParquetFileFormat

class MeasuredFactJoinExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit = ext.injectOptimizerRule { session =>
    val ex = session.experimental
    ex.synchronized {
      if (!ex.extraOptimizations.contains(MeasuredFactJoinOrder)) {
        ex.extraOptimizations = MeasuredFactJoinOrder +: ex.extraOptimizations
      }
    }
    new Rule[LogicalPlan] { override def apply(plan: LogicalPlan): LogicalPlan = plan }
  }
}

private[adaptive] object MeasuredFactJoinOrder extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.measuredFactJoinOrder"

  private def prunedScan(plan: LogicalPlan): Boolean = {
    def scan(p: LogicalPlan): Boolean = p match {
      case Project(cols,c) if cols.forall(_.isInstanceOf[Attribute]) => scan(c)
      case Filter(pred,c) if pred.deterministic => scan(c)
      case l: LogicalRelation if !l.isStreaming => l.relation match {
        case h: HadoopFsRelation => h.fileFormat.isInstanceOf[ParquetFileFormat] && h.partitionSchema.nonEmpty
        case _ => false
      }
      case _ => false
    }
    scan(plan) && plan.exists {
      case Filter(pred,_) => pred.exists(_.isInstanceOf[DynamicPruningSubquery])
      case _ => false
    }
  }

  private def keys(condition: Expression, l: LogicalPlan, r: LogicalPlan):
      Seq[(Attribute, Attribute)] = {
    val terms = splitConjunctivePredicates(condition)
    val cols = terms.collect { case EqualTo(a: Attribute,b: Attribute) if a.dataType == b.dataType => (a,b) }
      .flatMap { case (a,b) =>
        Seq((a,b),(b,a)).find { case (x,y) => l.outputSet.contains(x) && r.outputSet.contains(y) }
      }
    if (cols.size == terms.size) cols else Nil
  }

  private def rewrite(outer: Join, inner: Join, project: Project, mode: String): LogicalPlan = {
    val a = inner.left
    val b = inner.right
    val c = outer.right
    val ab = keys(inner.condition.get,a,b)
    val bc = keys(outer.condition.get,b,c)
    if (bc.size < 2 || ab.size <= bc.size || !bc.forall {
        case (k,_) => ab.exists(_._2.semanticEquals(k))
      } || !Seq(a,b,c).forall(prunedScan)) return outer

    val build = Some(HintInfo(Some(SHUFFLE_HASH)))
    if (mode == "originalHash") {
      val lower = inner.copy(hint = JoinHint(None, build))
      return outer.copy(left = project.copy(child = lower), hint = JoinHint(build,None))
    }
    val hash = Set("rotateHash","hashInner","measureHash").contains(mode)
    val lower = Join(b,c,Inner,outer.condition,if (hash) JoinHint(build,None) else JoinHint.NONE)
    val joined = Join(a,lower,Inner,inner.condition,if (mode == "rotateHash") JoinHint(None,build) else JoinHint.NONE)
    if (mode.startsWith("measure")) joined.setTagValue(FactBuildFirst.measure, true)
    // Restore the original projection and attribute order. Each predicate retains its
    // original expression IDs, null comparison, and duplicate-preserving inner-join semantics.
    Project(outer.output,joined)
  }

  override def apply(plan: LogicalPlan): LogicalPlan = {
    val mode = conf.getConfString(setting,"off")
    if (plan.isStreaming || !Set("originalHash","rotate","rotateHash","hashInner","measureHash","measureSort").contains(mode)) return plan
    plan.transformUp {
      case j @ Join(p @ Project(cols,i @ Join(_,_,Inner,Some(_),JoinHint.NONE)),
          _,Inner,Some(_),JoinHint.NONE) if cols.forall(_.isInstanceOf[Attribute]) =>
        rewrite(j,i,p,mode)
    }
  }
}
