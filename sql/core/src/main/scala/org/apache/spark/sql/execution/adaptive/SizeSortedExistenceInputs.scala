package org.apache.spark.sql.execution.adaptive

import org.apache.spark.sql.catalyst.optimizer.JoinSelectionHelper
import org.apache.spark.sql.catalyst.plans.LeftSemi
import org.apache.spark.sql.catalyst.plans.logical.statsEstimation.EstimationUtils
import org.apache.spark.sql.catalyst.plans.physical.{Distribution, HashPartitioning}
import org.apache.spark.sql.catalyst.rules.Rule
import org.apache.spark.sql.execution.{SortExec, SparkPlan}
import org.apache.spark.sql.execution.exchange.{ENSURE_REQUIREMENTS, ReusedExchangeExec, ShuffleExchangeExec, ValidateRequirements}
import org.apache.spark.sql.execution.joins.SortMergeJoinExec
import org.apache.spark.sql.internal.SQLConf

/** Size the two fresh inputs of a key-only existence join for their local sort working sets. */
case class SizeSortedExistenceInputs(
    required: Option[Distribution],
    cached: () => Set[SparkPlan]) extends Rule[SparkPlan] with JoinSelectionHelper {

  override def apply(plan: SparkPlan): SparkPlan = {
    def eligible(j: SortMergeJoinExec): Boolean = j.joinType == LeftSemi &&
      j.condition.isEmpty && !j.isSkewJoin && j.right.output.nonEmpty &&
      j.right.output.forall(a => j.rightKeys.exists(_.semanticEquals(a)))
    if (!conf.getConfString("spark.sql.adaptive.sizeSortedExistenceInputs.enabled", "false").toBoolean ||
        !plan.exists { case j: SortMergeJoinExec => eligible(j); case _ => false }) return plan
    // A pipelined task group fixes reader routing before either writer starts.
    if (plan.exists {
        case s: ShuffleExchangeExec => s.pipelined
        case r: ReusedExchangeExec => r.child match {
          case s: ShuffleExchangeExec => s.pipelined
          case _ => false
        }
        case _ => false
      }) return plan
    val current = conf.numShufflePartitions
    val sc = plan.session.sparkContext
    val slots = sc.maxNumConcurrentTasks(sc.resourceProfileManager.defaultResourceProfile)
    val shuffleManager = org.apache.spark.SparkEnv.get.shuffleManager
    if (shuffleManager.getClass != classOf[org.apache.spark.shuffle.sort.SortShuffleManager]) return plan
    // Crossing the bypass limit would also switch every producer to a different writer.
    // Preserve the writer chosen for the original exchange when growing its reducer count.
    val bypassLimit = sc.getConf.get(org.apache.spark.internal.config.SHUFFLE_SORT_BYPASS_MERGE_THRESHOLD)
    val available = if (current <= bypassLimit) math.min(slots, bypassLimit) else slots
    if (available <= current) return plan

    val explicit = plan.collectWithSubqueries { case r: ReusedExchangeExec => r.child.canonicalized }
    val all = plan.collectWithSubqueries { case s: ShuffleExchangeExec => s.canonicalized }
    val shared = cached() ++ explicit ++ all.groupMapReduce(identity)(_ => 1)(_ + _).collect {
      case (owner, n) if n > 1 => owner
    }
    val estimateConf = conf.clone()
    estimateConf.setConf(SQLConf.HASH_JOIN_EQUI_JOIN_SIZE_ESTIMATE, true)
    val advisory = conf.getConf(SQLConf.ADVISORY_PARTITION_SIZE_IN_BYTES)
    def input(p: SparkPlan): Option[(SortExec, ShuffleExchangeExec, HashPartitioning, BigInt)] =
      p match {
        case sort: SortExec if !sort.global => sort.child match {
          case e: ShuffleExchangeExec if !e.pipelined && e.shuffleOrigin == ENSURE_REQUIREMENTS &&
              !shared.contains(e.canonicalized) => (e.outputPartitioning, e.child.logicalLink) match {
            case (h: HashPartitioning, Some(logical)) if h.numPartitions == current &&
                logical.collectLeaves().forall(_.stats.sizeInBytes < conf.defaultSizeInBytes) =>
              // UnsafeInMemorySorter stores a record pointer and a sort prefix for each row.
              // Include these resident longs along with the projected row payload.
              val bytes = pipelinedPolicyRowEstimate(logical, estimateConf) *
                (EstimationUtils.getSizePerRow(logical.output) + 2 * java.lang.Long.BYTES)
              Some((sort, e, h, bytes))
            case _ => None
          }
          case _ => None
        }
        case _ => None
      }

    val sized = plan.transformUp {
      case j: SortMergeJoinExec if eligible(j) =>
        (for (lhs <- input(j.left); rhs <- input(j.right)) yield {
          val width = ((lhs._4.max(rhs._4) + advisory - 1) / advisory).min(available).toInt
          if (width <= current) j else {
            val children = Seq(lhs, rhs).map { case (sort, exchange, hash, _) =>
              sort.copy(child = exchange.copy(outputPartitioning = hash.copy(numPartitions = width)))
            }
            j.withNewChildren(children)
          }
        }).getOrElse(j)
    }
    if ((plan eq sized) || required.fold(ValidateRequirements.validate(sized))(
        d => ValidateRequirements.validate(sized, d))) sized else plan
  }
}
