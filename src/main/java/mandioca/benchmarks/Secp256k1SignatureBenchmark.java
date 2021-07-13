package mandioca.benchmarks;

import mandioca.bitcoin.ecc.*;
import org.openjdk.jmh.annotations.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.util.concurrent.TimeUnit;

import static java.math.BigInteger.ONE;
import static java.math.BigInteger.TWO;
import static mandioca.bitcoin.ecc.curveparams.EllipticCurveName.SECP256K1;
import static mandioca.bitcoin.function.BigIntegerFunctions.wrap;
import static mandioca.bitcoin.util.HashUtils.getDoubleSHA256HashAsInteger;
import static mandioca.bitcoin.util.HexUtils.HEX;

@Warmup(iterations = 1)
@Measurement(iterations = 3)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1) // A new JVM is forked to minimize the effects and optimizations of one specific JVM run.
public class Secp256k1SignatureBenchmark {

    private static final Logger log = LoggerFactory.getLogger(Secp256k1SignatureBenchmark.class);

    static final String CURVE_EQ = "y^2 = x^3 + ax + b";
    protected static final EllipticCurve SECP256K1_CURVE = new EllipticCurve(SECP256K1);
    protected static final Field A = SECP256K1_CURVE.getA();  // constant finite field (a, p), where a = 0
    protected static final Field B = SECP256K1_CURVE.getB();  // constant finite field (b, p), where b = 7
    protected static final BigInteger P = SECP256K1_CURVE.getP();  // finite field prime order p
    protected static final Secp256k1Point G = (Secp256k1Point) SECP256K1_CURVE.getG(); // curve's generator point G
    protected static final BigInteger N = SECP256K1_CURVE.getN();  // curve's group order N
    protected static final Secp256k1Point IDENTITY = (Secp256k1Point) SECP256K1_CURVE.getIdentity(); // curve's identity pt at infinity

    @Benchmark
    public void testSecp256k1Signature() {
        testVerificationAlgorithm();
        testVerifySignature1();
        testVerifySignature2();
        testVerifySignature3();
        testCreateSignatureExampleOnPage68ToBeDeprecatedWithRFC6979();
        testExercise7OnPage69ToBeDeprecatedWithRFC6979();
        testDer1();
    }


    private void testVerificationAlgorithm() {
        BigInteger z = HEX.stringToBigInt.apply("0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423");
        BigInteger r = HEX.stringToBigInt.apply("0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6");
        BigInteger s = HEX.stringToBigInt.apply("0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec");
        Signature signature = new Signature(r, s);

        BigInteger px = HEX.stringToBigInt.apply("0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574");
        BigInteger py = HEX.stringToBigInt.apply("0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4");

        BigInteger sigInverse = s.modPow(N.subtract(TWO), N);  /* pow(s, N-2, N) */
        BigInteger expectedSInv = new BigInteger("83315713936566224420015412661015577547690689064140914253930493048760670735557");
        assert expectedSInv.equals(sigInverse);

        BigInteger expectedU = new BigInteger("24204376172060088355173148117943432505866159603238948537164087226614374166398");
        BigInteger u = z.multiply(sigInverse).mod(N);    //  u = z * s_inv % N
        assert expectedU.equals(u);

        BigInteger expectedV = new BigInteger("3568077940363585637313312393642167316668044014921753482828979604339392210476");
        BigInteger v = signature.getR().multiply(sigInverse).mod(N);   // v = r * s_inv % N
        assert expectedV.equals(v);

        Secp256k1Point p = getPoint(px, py);
        Secp256k1Point uG = G.scalarMultiply(u);
        Secp256k1Point vP = p.scalarMultiply(v);
        Secp256k1Point uGAddvP = uG.add(vP);
        assert uGAddvP.getX().getNumber().equals(r);
        assert p.verify(z, signature) == true;
    }


    private void testVerifySignature1() {
        BigInteger px = HEX.stringToBigInt.apply("0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c");
        BigInteger py = HEX.stringToBigInt.apply("0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34");
        Secp256k1Point p = getPoint(px, py);

        BigInteger z = HEX.stringToBigInt.apply("0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60"); // sig-hash
        BigInteger r = HEX.stringToBigInt.apply("0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395");
        BigInteger s = HEX.stringToBigInt.apply("0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4");
        Signature signature = new Signature(r, s);
        assert p.verify(z, signature) == true;
    }


    private void testVerifySignature2() {
        BigInteger z = HEX.stringToBigInt.apply("0xbc62d4b80d9e36da29c16c5d4d9f11731f36052c72401a76c23c0fb5a9b74423"); // sig-hash
        BigInteger r = HEX.stringToBigInt.apply("0x37206a0610995c58074999cb9767b87af4c4978db68c06e8e6e81d282047a7c6"); // x coordinate of R
        BigInteger s = HEX.stringToBigInt.apply("0x8ca63759c1157ebeaec0d03cecca119fc9a75bf8e6d0fa65c841c8e2738cdaec");
        Signature signature = new Signature(r, s);
        BigInteger px = HEX.stringToBigInt.apply("0x04519fac3d910ca7e7138f7013706f619fa8f033e6ec6e09370ea38cee6a7574");
        BigInteger py = HEX.stringToBigInt.apply("0x82b51eab8c27c66e26c858a079bcdf4f1ada34cec420cafc7eac1a42216fb6c4");
        Secp256k1Point p = getPoint(px, py);
        assert p.verify(z, signature) == true;
    }


    private void testVerifySignature3() {
        BigInteger z = HEX.stringToBigInt.apply("0xec208baa0fc1c19f708a9ca96fdeff3ac3f230bb4a7ba4aede4942ad003c0f60"); // sig-hash
        BigInteger r = HEX.stringToBigInt.apply("0xac8d1c87e51d0d441be8b3dd5b05c8795b48875dffe00b7ffcfac23010d3a395"); // x coordinate of R
        BigInteger s = HEX.stringToBigInt.apply("0x68342ceff8935ededd102dd876ffd6ba72d6a427a3edb13d26eb0781cb423c4");
        Signature signature = new Signature(r, s);
        BigInteger px = HEX.stringToBigInt.apply("0x887387e452b8eacc4acfde10d9aaf7f6d9a0f975aabb10d006e4da568744d06c");
        BigInteger py = HEX.stringToBigInt.apply("0x61de6d95231cd89026e286df3b6ae4a894a3378e393e93a0f45b666329a0ae34");
        Secp256k1Point p = getPoint(px, py);
        assert p.verify(z, signature) == true;
    }


    private void testCreateSignatureExampleOnPage68ToBeDeprecatedWithRFC6979() {
        String mySecret = "my secret";
        String myMessage = "my message";
        BigInteger e = getDoubleSHA256HashAsInteger(mySecret);  // private key
        BigInteger z = getDoubleSHA256HashAsInteger(myMessage); // signature hash // TODO Should it be dbl hashed as in the book?

        // TODO using deterministic k breaks this test because K != 1234567890
        // Rfc6979 deterministicKalkulator = new Rfc6979();
        // deterministicKalkulator.init(e, z);
        // BigInteger k = deterministicKalkulator.nextK();
        BigInteger k = BigInteger.valueOf(1234567890); // a 'random' number  (deterministic k will break this test)

        BigInteger kInverse = k.modPow(N.subtract(TWO), N); // TODO see if'inverse' func can be called from curve param map
        BigInteger r = G.scalarMultiply(k).x.getNumber(); // x coordinate of kG
        BigInteger s = z.add(r.multiply(e)).multiply(kInverse).mod(N);   // ((z + r*e) * kInv) % N, or s=(z+re)/k mod N
        Point point = G.scalarMultiply(e);    // P = eG, the public point (key) is known by the verifier

        /*
        out.printf("my secret: '%s'      my message: '%s'\n", mySecret, myMessage);
        out.println("e:     " + HEX.to64DigitPaddedHex(e));
        out.println("z:     " + HEX.to64DigitPaddedHex(z));
        out.println("k:     " + HEX.to64DigitPaddedHex(k));
        out.println("kInv:  " + HEX.to64DigitPaddedHex(kInverse));
        out.println("r:     " + HEX.to64DigitPaddedHex(r));
        out.println("s:     " + HEX.to64DigitPaddedHex(s));
        out.println("point: " + point);
         */

        assert "8b387de39861728c92ec9f589c303b1038ff60eb3963b12cd212263a1d1e0f00".equals(HEX.to64DigitPaddedHex(e));
        assert "0231c6f3d980a6b0fb7152f85cee7eb52bf92433d9919b9c5218cb08e79cce78".equals(HEX.to64DigitPaddedHex(z));
        assert "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22".equals(HEX.to64DigitPaddedHex(r));
        assert "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9".equals(HEX.to64DigitPaddedHex(s));
        Point expected = getPoint(
                new BigInteger("028d003eab2e428d11983f3e97c3fa0addf3b42740df0d211795ffb3be2f6c52", 16),
                new BigInteger("0ae987b9ec6ea159c78cb2a937ed89096fb218d9e7594f02b547526d8cd309e2", 16));
        assert expected.equals(point);

        Secp256k1PrivateKey pKey = new Secp256k1PrivateKey(e);
        Signature signature = pKey.sign(z, k);
        // out.println("signature: " + signature);
        assert "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22".equals(HEX.to64DigitPaddedHex(signature.getR()));

        // Assert(s) fails because
        //    if (s.compareTo(n.divide(TWO)) > 0) {
        //        s = n.subtract(s); // a low s value induces bitcoin nodes to relay our transactions for malleability reasons.
        //    }
        // assert "bb14e602ef9e3f872e25fad328466b34e6734b7a0fcd58b1eb635447ffae8cb9", paddedHex(signature.getS()));

    }


    private void testExercise7OnPage69ToBeDeprecatedWithRFC6979() {
        String mySecret = "12345"; // already double-hashed
        String myMessage = "Programming Bitcoin!";
        BigInteger e = new BigInteger(mySecret);
        BigInteger z = getDoubleSHA256HashAsInteger(myMessage); // signature hash  // TODO Should it be dbl hashed as in the book?
        // TODO using deterministic k breaks this test because K != 1234567890
        // Rfc6979 deterministicKalkulator = new Rfc6979();
        // deterministicKalkulator.init(e, z);
        // BigInteger k = deterministicKalkulator.nextK();
        BigInteger k = BigInteger.valueOf(1234567890); // a 'random' number (deterministic k will break this test)
        BigInteger kInverse = k.modPow(N.subtract(TWO), N); // TODO see if'inverse' func can be called from curve param map
        BigInteger r = G.scalarMultiply(k).x.getNumber(); // x coordinate of kG
        BigInteger s = z.add(r.multiply(e)).multiply(kInverse).mod(N);   // ((z + r*e) * kInv) % N, or s=(z+re)/k mod N
        Point point = G.scalarMultiply(e);    // P = eG, the public point (key) is known by the verifier

        /*
        out.printf("my secret: '%s'      my message: '%s'\n", mySecret, myMessage);
        out.println("e:     " + HEX.to64DigitPaddedHex(e));
        out.println("z:     " + HEX.to64DigitPaddedHex(z));
        out.println("k:     " + HEX.to64DigitPaddedHex(k));
        out.println("kInv:  " + HEX.to64DigitPaddedHex(kInverse));
        out.println("r:     " + HEX.to64DigitPaddedHex(r));
        out.println("s:     " + HEX.to64DigitPaddedHex(s));
        out.println("point: " + point);
         */

        assert "0000000000000000000000000000000000000000000000000000000000003039".equals(HEX.to64DigitPaddedHex(e));
        assert "969f6056aa26f7d2795fd013fe88868d09c9f6aed96965016e1936ae47060d48".equals(HEX.to64DigitPaddedHex(z));
        assert "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22".equals(HEX.to64DigitPaddedHex(r));
        assert "1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a".equals(HEX.to64DigitPaddedHex(s));
        Point expected = getPoint(
                new BigInteger("f01d6b9018ab421dd410404cb869072065522bf85734008f105cf385a023a80f", 16),
                new BigInteger("0eba29d0f0c5408ed681984dc525982abefccd9f7ff01dd26da4999cf3f6a295", 16));
        assert expected.equals(point);

        Secp256k1PrivateKey pKey = new Secp256k1PrivateKey(e);
        Signature signature = pKey.sign(z, k);
        // out.println("signature: " + signature);
        assert "2b698a0f0a4041b77e63488ad48c23e8e8838dd1fb7520408b121697b782ef22".equals(HEX.to64DigitPaddedHex(signature.getR()));
        // Assert(s) fails because
        //    if (s.compareTo(n.divide(TWO)) > 0) {
        //        s = n.subtract(s); // a low s value induces bitcoin nodes to relay our transactions for malleability reasons.
        //    }
        // assert "1dbc63bfef4416705e602a7b564161167076d8b20990a0f26f316cff2cb0bc1a", paddedHex(signature.getS()));
    }

    // From Jimmy Song Book, Chapter 4, Exercise 3
    private void testDer1() {
        BigInteger z = getDoubleSHA256HashAsInteger("message"); // signature hash  // TODO Should it be dbl hashed as in the book?
        Secp256k1PrivateKey privateKey = new Secp256k1PrivateKey(ONE);
        Signature signature = privateKey.sign(z, BigInteger.valueOf(1234567890));
        byte[] der = signature.getDer();
        //  out.println("der: " + HEX.encode(der));
        /*
        String expectedSec = "02" // marker for y is even
                + "96be5b1292f6c856b3c5654e886fc13511462059089cdf9c479623bfcbe77690";    // x-coordinate
         assert expectedSec, bytesToHex(publicKey.getSec(true)));
         */
    }

    protected EllipticCurve getCurve(int a, int b, int p) {
        return new EllipticCurve(SECP256K1.name(), CURVE_EQ,
                wrap.apply(a), wrap.apply(b), wrap.apply(p),
                null, null, null);
    }

    protected Point getPoint(EllipticCurve ec, int x, int y) {
        return ec.getPoint(wrap.apply(x), wrap.apply(y));
    }

    protected Secp256k1Point getPoint(BigInteger x, BigInteger y) {
        return (Secp256k1Point) SECP256K1_CURVE.getPoint(x, y);
    }
}
