# graalvm-eec-benchmark
GraalVM 16 vs OpenJDK 16 EEC Comparison

Investigated benefits of using GraalVM https://www.graalvm.org.

Tests in https://github.com/ghubstan/graalvm-eec-benchmark/tree/main/src/test/java/mandioca/benchmarks provided 
some performance comparisons between the GraalVM 16 jvm, and conventional OpenJDK 16's jvm.

The measurements below show the GraalVM is not significantly faster than the OpenJDK 16 jvm 
(on my 16 core Linux machine).

	For some hash to address functions, no improvement.

		// Test Results OpenJDK 16
		//  3.956 ±(99.9%) 0.275 ms/op [Average]
		//  3.814 ±(99.9%) 0.408 ms/op [Average]

		// Test Results GraalVM 16
		// Result "mandioca.benchmarks.HashToAddressBenchmark.testHashesToAddresses":
		//  3.821 ±(99.9%) 0.409 ms/op [Average]
		//  3.792 ±(99.9%) 0.112 ms/op [Average]
		
		GraalVM is 0.5 % faster?

	For some Secp256k1 signature generation and verification functions, no improvement.

		// OpenJDK 16
		// Result "mandioca.benchmarks.Secp256k1SignatureBenchmark.testSecp256k1Signature":
		//  109.681 ±(99.9%) 11.444 ms/op [Average]
		//  106.823 ±(99.9%) 0.489 ms/op [Average]

		// GraalVM 16
		// Result "mandioca.benchmarks.Secp256k1SignatureBenchmark.testSecp256k1Signature":
		//  105.321 ±(99.9%) 7.760 ms/op [Average]
		//  109.602 ±(99.9%) 8.908 ms/op [Average]

	For a deterministic K calculator based on the algorithm defined in section 3.2 of RFC 6979, no improvement.

		// Test Results OpenJDK 16
		// Result "mandioca.benchmarks.Rfc6979Benchmark.testRfc6979_K":
		//  109.681 ±(99.9%) 11.444 ms/op [Average]
		//  106.823 ±(99.9%) 0.489 ms/op [Average]
		

		// Test Results GraalVM 16
		// Result "mandioca.benchmarks.Rfc6979Benchmark.testRfc6979_K":
		//  0.275 ±(99.9%) 0.031 ms/op [Average]
		//  0.280 ±(99.9%) 0.022 ms/op [Average]


I used the GraalVM native image builder to get some performance and memory footprint comparisons between native 
binaries built with GraalVM 16, and conventional java binaries built with OpenJDK 16.
Running the same test cases, alternating between the OpenJDK 16 runtime, and the native image built with GraalVM, 
I found:

- The native image's java heap was ~43% bigger than the heap size of the app when running on OpenJDK 16's jvm.

- The native image's resident memory (OS physical memory) use was ~45% smaller than the heap size of the app when running on OpenJDK 16's jvm.

- No significance difference was found in performance.


I also built a native image from Bisq's desktop-all.jar, but it wouldn't run due to reflection related class-not-found 
errors.  The broken native app's size was 38 Mb, as compared to ~ 140Mb size of the current master's desktop-all.jar.

A native image built from a bare bones project containing a small subset of Bisq dependencies failed at startup due to 
Logger initialization code in 3rd party libaries.

We (@chimp1984 and I) decided to not spend more time debugging GraalVM native image builds, in part because of the 
known issues with the experimental feature:  https://www.graalvm.org/release-notes/known-issues.

