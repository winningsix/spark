# M4 Spark batch shuffle PoC

The baseline is the Java Spark build used for the paired TPC-DS SF1000 run
`regfixfullds99157`. Each arm executed all 103 SQL statements twice.
The 99 query totals in [tpcds-warm.csv](tpcds-warm.csv) use the warm executions
and sum both statements for multipart queries. The run validated the result
rows for both arms. RTM was faster than or equal to BSP on 42 queries. The
final RTM plans used pipelining for 438 of 567 shuffle exchanges.

## Build identity and replay

[build.json](build.json) records the timed build, input and output JAR digests,
and the runtime JAR inventory. [tpcds-profile.json](tpcds-profile.json) records
portable SQL and shuffle settings for each arm and the separate Gluten artifact
digest. The perf run used a patched Spark 5.0 snapshot and an external Gluten
JAR. Keep the rest of the measured distribution and the SF1000 input fixed when
comparing timings.

The source changes are in the Spark modules. The two extension sources under
`extensions/` need the Gluten JAR at compile time. The standalone indexed build
extension under `indexed-build-join/` and the timed collect helper under
`benchmark/` came from separate benchmark JARs.

To reproduce the three measured JARs exactly, supply the two input JARs whose
digests appear under `base_jars_sha256` and choose a new output directory.
The replay script checks the input and output hashes. This binary replay also
preserves ZIP headers and entries retained by the original overlay build.

```sh
python3 dev/m4-poc/replay/replay.py /path/to/base/spark/jars /path/to/new-jars
```

## Independent candidates

Each patch applies directly to the baseline commit. Select one for an isolated
comparison with the original SQL and the same-build BSP arm.

| Query | Candidate |
| --- | --- |
| Q16, Q94 | [Reserve writer capacity for consecutive membership joins](candidates/writer-wave-q16-q94.patch) |
| Q23 | [Reuse partial counts across filtered membership joins](candidates/joined-count-reuse-q23.patch) |
| Q24 | [Stage dimension joins before the grouped threshold](candidates/threshold-lookups-q24.patch) |
| Q47, Q57 | [Compute both rank neighbors from one ranked input](candidates/ranked-neighbors-q47-q57.patch) |
| Q65 | [Batch the window aggregate shuffle](candidates/window-merge-q65.patch) |
| Q78 | [Materialize inputs of concurrent grouped joins](candidates/grouped-inputs-q78.patch) |
| Q93 | [Apply the reason dimension before the composite fact join](candidates/filtered-composite-q93.patch) |

The published full-suite measurements apply to the baseline. Candidate patches
have separate benchmark identities.
