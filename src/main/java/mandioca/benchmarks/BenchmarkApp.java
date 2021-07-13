package mandioca.benchmarks;

import mandioca.benchmarks.bash.RunBashCommand;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class BenchmarkApp {

    private static final Logger log = LoggerFactory.getLogger(BenchmarkApp.class);

    public BenchmarkApp() {
    }

    public void run() {
        log.info("Starting benchmark jobs ...");

        log.info("Running HashToAddressBenchmark");
        HashToAddressBenchmark hashToAddressBenchmark = new HashToAddressBenchmark();
        hashToAddressBenchmark.testHashesToAddresses();

        log.info("Running Rfc6979Benchmark");
        Rfc6979Benchmark rfc6979Benchmark = new Rfc6979Benchmark();
        rfc6979Benchmark.testRfc6979_K();

        log.info("Running Rfc6979Benchmark");
        Secp256k1SignatureBenchmark secp256k1SignatureBenchmark = new Secp256k1SignatureBenchmark();
        secp256k1SignatureBenchmark.testSecp256k1Signature();

        // https://github.com/ghubstan/bisq/commit/a14613d46cfc5aca34799fac027cb791bec476ec

        RunBashCommand.printSystemLoad(log, new RuntimeException("System Load"));
    }

    public static void main(String[] args) {
        BenchmarkApp benchmarkApp = new BenchmarkApp();
        benchmarkApp.run();
    }
}
