package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.{SparkSessionExtensions, SparkSessionExtensionsProvider}
import org.apache.spark.sql.catalyst.expressions._
import org.apache.spark.sql.catalyst.plans.Inner
import org.apache.spark.sql.catalyst.plans.logical._
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.datasources.{HadoopFsRelation, LogicalRelation}

class CompositeFactJoinExtension extends SparkSessionExtensionsProvider {
  override def apply(ext: SparkSessionExtensions): Unit =
    ext.injectPreCBORule(_ => CompositeFactJoin)
}

private[adaptive] object CompositeFactJoin extends Rule[LogicalPlan] with PredicateHelper {
  val setting = "spark.sql.optimizer.deriveCompositeFactJoinKeys"

  private case class Spine(base: Join, lookups: Vector[(LogicalPlan, Seq[Expression])])

  private def fileInput(p: LogicalPlan): Boolean = p match {
    case Project(cols, child) if cols.forall(_.isInstanceOf[Attribute]) => fileInput(child)
    case Filter(c, child) if c.deterministic && !SubqueryExpression.hasSubquery(c) => fileInput(child)
    case l: LogicalRelation => !l.isStreaming && l.relation.isInstanceOf[HadoopFsRelation]
    case _ => false
  }

  private def spine(p: LogicalPlan): Option[Spine] = p match {
    case Project(cols, c) if cols.forall(_.isInstanceOf[Attribute]) => spine(c)
    case j @ Join(l,r,Inner,Some(c),JoinHint.NONE)
        if c.deterministic && !SubqueryExpression.hasSubquery(c) && fileInput(r) =>
      val conditions=splitConjunctivePredicates(c)
      if (fileInput(l)) {
        val hasRange=conditions.exists {
          case LessThan(_:Attribute,_:Attribute) | GreaterThan(_:Attribute,_:Attribute) => true
          case _ => false
        }
        val hasEqui=conditions.exists {case EqualTo(_:Attribute,_:Attribute)=>true;case _=>false}
        Option.when(hasRange && hasEqui)(Spine(j,Vector.empty))
      } else spine(l).map(s=>s.copy(lookups=s.lookups :+ (r->conditions)))
    case _ => None
  }

  private def connects(e: Expression, a: AttributeSet, b: AttributeSet): Boolean = e match {
    case EqualTo(x:Attribute,y:Attribute) => (a.contains(x) && b.contains(y)) ||
      (a.contains(y) && b.contains(x))
    case _ => false
  }

  private def rewrite(j:Join, mode:String):Option[LogicalPlan]=spine(j).flatMap { s =>
    val base=s.base
    // Choose two dimensions with a direct key to opposite inputs and an equality to each other.
    val bridges=for {
      (a,i)<-s.lookups.zipWithIndex
      (b,k)<-s.lookups.zipWithIndex if i<k
      leftFirst= a._2.exists(connects(_,a._1.outputSet,base.left.outputSet)) &&
        b._2.exists(connects(_,b._1.outputSet,base.right.outputSet))
      rightFirst= a._2.exists(connects(_,a._1.outputSet,base.right.outputSet)) &&
        b._2.exists(connects(_,b._1.outputSet,base.left.outputSet))
      if (leftFirst || rightFirst) && b._2.exists(connects(_,a._1.outputSet,b._1.outputSet))
    } yield Set(i,k)
    bridges.headOption.map { bridge =>
      var left=base.left
      var right=base.right
      var pending=splitConjunctivePredicates(base.condition.get).toVector
      var later=Vector.empty[(LogicalPlan,Seq[Expression])]
      for (((dim,cs),i)<-s.lookups.zipWithIndex) {
        val onLeft=cs.exists(connects(_,dim.outputSet,left.outputSet))
        val onRight=cs.exists(connects(_,dim.outputSet,right.outputSet))
        // A lookup with two distinct connections to accumulated branches follows the original
        // fact-key connection. The cross-branch equality then becomes a join key.
        val directLeft=cs.exists(connects(_,dim.outputSet,base.left.outputSet))
        val directRight=cs.exists(connects(_,dim.outputSet,base.right.outputSet))
        val side=if (directLeft!=directRight) Some(directLeft)
          else if (onLeft!=onRight) Some(onLeft) else None
        if ((bridge(i) || mode=="filters") && side.isDefined) {
          val isLeft=side.get
          val in=if(isLeft) left else right
          val available=in.outputSet ++ dim.outputSet
          val (ready,rest)=cs.partition(_.references.subsetOf(available))
          val joined=Join(in,dim,Inner,Some(ready.reduceLeft(And)),JoinHint.NONE)
          if(isLeft) left=joined else right=joined
          pending++=rest
        } else later :+= dim->cs
      }
      val available=left.outputSet ++ right.outputSet
      val (now,extra)=pending.partition(_.references.subsetOf(available))
      var result:LogicalPlan=Join(left,right,Inner,Some(now.reduceLeft(And)),JoinHint.NONE)
      for ((dim,cs)<-later) result=Join(result,dim,Inner,Some(cs.reduceLeft(And)),JoinHint.NONE)
      if(extra.nonEmpty) result=Filter(extra.reduceLeft(And),result)
      // This rule runs after column pruning. Prune again so foreign keys used only by a
      // moved lookup do not inflate the fact-to-fact shuffle.
      org.apache.spark.sql.catalyst.optimizer.ColumnPruning(Project(j.output,result))
    }
  }

  override def apply(p:LogicalPlan):LogicalPlan={
    val mode=conf.getConfString(setting,"off")
    if(p.isStreaming || !Set("keys","filters").contains(mode)) p
    else p.transformDown {case j:Join if j.joinType==Inner=>rewrite(j,mode).getOrElse(j)}
  }
}
