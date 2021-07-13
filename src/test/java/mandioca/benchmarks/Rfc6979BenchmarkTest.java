package mandioca.benchmarks;

import org.junit.Test;
import org.openjdk.jmh.results.RunResult;
import org.openjdk.jmh.runner.Runner;
import org.openjdk.jmh.runner.RunnerException;
import org.openjdk.jmh.runner.options.Options;
import org.openjdk.jmh.runner.options.OptionsBuilder;

import java.text.DecimalFormat;
import java.util.Collection;

import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

// https://www.retit.de/continuous-benchmarking-with-jmh-and-junit-2/
// https://www.awesome-testing.com/2019/05/performance-testing-benchmarking-java.html

public class Rfc6979BenchmarkTest {

    //////////////////////////
    // Test Results OpenJDK 16
    //////////////////////////
    // Result "mandioca.benchmarks.Rfc6979Benchmark.testRfc6979_K":
    //  0.302 ±(99.9%) 0.005 ms/op [Average]
    //  0.301 ±(99.9%) 0.011 ms/op [Average]

    //////////////////////////
    // Test Results GraalVM 16
    //////////////////////////
    // Result "mandioca.benchmarks.Rfc6979Benchmark.testRfc6979_K":
    //  0.275 ±(99.9%) 0.031 ms/op [Average]
    //  0.280 ±(99.9%) 0.022 ms/op [Average]

    // 8% better

    private static DecimalFormat df = new DecimalFormat("0.000");
    private static final double REFERENCE_SCORE = 171.000;

    @Test
    public void runHashToAddressBenchmark() throws RunnerException {
        Options opt = new OptionsBuilder()
                .include(Rfc6979Benchmark.class.getSimpleName())
                .build();
        Collection<RunResult> runResults = new Runner(opt).run();
        assertFalse(runResults.isEmpty());
        for (RunResult runResult : runResults) {
            // assertDeviationWithin(runResult, REFERENCE_SCORE, 0.05);
        }
    }

    private static void assertDeviationWithin(RunResult result, double referenceScore, double maxDeviation) {
        double score = result.getPrimaryResult().getScore();
        double deviation = Math.abs(score / referenceScore - 1);
        String deviationString = df.format(deviation * 100) + "%";
        String maxDeviationString = df.format(maxDeviation * 100) + "%";
        String errorMessage = "Deviation " + deviationString + " exceeds maximum allowed deviation " + maxDeviationString;
        assertTrue(errorMessage, deviation < maxDeviation);
    }
}
