package org.apache.spark.sql.execution

import org.apache.spark.sql.catalyst.InternalRow
import org.apache.spark.sql.catalyst.expressions.Expression
import org.apache.spark.sql.catalyst.expressions.aggregate.TypedImperativeAggregate
import org.apache.spark.sql.catalyst.trees.UnaryLike
import org.apache.spark.sql.types.{BinaryType, DataType}

case class CollectCompactKeyBitmap(
    child: Expression,
    byteBudget: Int,
    override val mutableAggBufferOffset: Int = 0,
    override val inputAggBufferOffset: Int = 0)
  extends TypedImperativeAggregate[CompactKeyBuffer] with UnaryLike[Expression] {

  override def dataType: DataType = BinaryType
  override def nullable: Boolean = true
  override def createAggregationBuffer(): CompactKeyBuffer = new CompactKeyBuffer(byteBudget)
  override def update(buffer: CompactKeyBuffer, row: InternalRow): CompactKeyBuffer = {
    val v = child.eval(row)
    if (v != null) buffer.add(v.asInstanceOf[Long])
    buffer
  }
  override def merge(buffer: CompactKeyBuffer, other: CompactKeyBuffer): CompactKeyBuffer = {
    buffer.merge(other)
    buffer
  }
  override def eval(buffer: CompactKeyBuffer): Any = buffer.finish()
  override def serialize(buffer: CompactKeyBuffer): Array[Byte] = buffer.partial()
  override def deserialize(bytes: Array[Byte]): CompactKeyBuffer = CompactKeyBuffer.restore(bytes, byteBudget)
  override def withNewMutableAggBufferOffset(offset: Int): CollectCompactKeyBitmap =
    copy(mutableAggBufferOffset = offset)
  override def withNewInputAggBufferOffset(offset: Int): CollectCompactKeyBitmap =
    copy(inputAggBufferOffset = offset)
  override protected def withNewChildInternal(c: Expression): CollectCompactKeyBitmap = copy(child = c)
}

