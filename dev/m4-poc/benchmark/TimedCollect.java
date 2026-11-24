package org.apache.spark.sql.benchmark;
import java.util.List;
import org.apache.spark.sql.Dataset;
import org.apache.spark.sql.Row;
import org.apache.spark.sql.SparkSession;

/** Benchmark-only clock for the published Java Spark SQL plus collectAsList scope. */
public final class TimedCollect {
    public final Dataset<Row> frame;
    public final List<Row> rows;
    public final long nanos;
    private TimedCollect(Dataset<Row> frame, List<Row> rows, long nanos) {
        this.frame = frame;
        this.rows = rows;
        this.nanos = nanos;
    }
    public static TimedCollect run(SparkSession session, String sql) {
        long start = System.nanoTime();
        Dataset<Row> frame = session.sql(sql);
        List<Row> rows = frame.collectAsList();
        return new TimedCollect(frame, rows, System.nanoTime() - start);
    }
    public double seconds() { return nanos / 1.0e9; }
    public Dataset<Row> resultFrame() { return frame; }
    public String rowsJson() {
        StringBuilder out = new StringBuilder("[");
        for (int i = 0; i < rows.size(); i++) {
            if (i != 0) out.append(',');
            out.append(rows.get(i).json());
        }
        return out.append(']').toString();
    }
}
