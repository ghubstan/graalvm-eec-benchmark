package mandioca.benchmarks;


import mandioca.bitcoin.address.Address;
import mandioca.bitcoin.ecc.Secp256k1Point;
import mandioca.bitcoin.ecc.Secp256k1PrivateKey;
import org.openjdk.jmh.annotations.*;

import java.math.BigInteger;
import java.util.concurrent.TimeUnit;

import static mandioca.bitcoin.address.AddressFactory.*;
import static mandioca.bitcoin.address.AddressType.P2PKH;
import static mandioca.bitcoin.network.NetworkType.MAINNET;
import static mandioca.bitcoin.network.NetworkType.TESTNET3;
import static mandioca.bitcoin.util.HexUtils.HEX;

@Warmup(iterations = 1)
@Measurement(iterations = 3)
@BenchmarkMode(Mode.AverageTime)
@OutputTimeUnit(TimeUnit.MILLISECONDS)
@Fork(1) // A new JVM is forked to minimize the effects and optimizations of one specific JVM run.
public class HashToAddressBenchmark {

    @Benchmark
    public void testHashesToAddresses() {
        testHashToP2pkhMainnetAddress();
        testHashToP2pkhTestnetAddress();
        testHashToP2shMainnetAddress();
        testHashToP2shTestnetAddress();
        testPrivateKeyToP2pkhTestnetAddress1();
        testPrivateKeyToP2pkhTestnetAddress2();
        testPrivateKeyToP2pkhMainnetAddress1();
    }

    private void testHashToP2pkhMainnetAddress() {
        // Test params from programmingbitcoin/code-ch08/helper.py  def test_p2pkh_address(self)
        byte[] hash = HEX.decode("74d691da1574e6b3c192ecfb52cc8984ee7b6c56");
        String expectedAddress = "1BenRpVUFK65JFWcQSuHnJKzc4M8ZP8Eqa";
        Address actualAddress = scriptHashToP2pkh.apply(hash, MAINNET);
        assert expectedAddress.equals(actualAddress.value());
    }

    private void testHashToP2pkhTestnetAddress() {
        // Test params from programmingbitcoin/code-ch08/helper.py   def test_p2pkh_address(self)
        byte[] hash = HEX.decode("74d691da1574e6b3c192ecfb52cc8984ee7b6c56");
        String expectedAddress = "mrAjisaT4LXL5MzE81sfcDYKU3wqWSvf9q";
        Address actualAddress = scriptHashToP2pkh.apply(hash, TESTNET3);
        assert expectedAddress.equals(actualAddress.value());
    }

    private void testHashToP2shMainnetAddress() {
        // Test params from programmingbitcoin/code-ch08/helper.py  def test_p2sh_address(self)
        byte[] hash = HEX.decode("74d691da1574e6b3c192ecfb52cc8984ee7b6c56");
        String expectedAddress = "3CLoMMyuoDQTPRD3XYZtCvgvkadrAdvdXh";
        Address actualAddress = scriptHashToP2sh.apply(hash, MAINNET);
        assert expectedAddress.equals(actualAddress.value());
    }

    private void testHashToP2shTestnetAddress() {
        // Test params from programmingbitcoin/code-ch08/helper.py  def test_p2sh_address(self)
        byte[] hash = HEX.decode("74d691da1574e6b3c192ecfb52cc8984ee7b6c56");
        String expectedAddress = "2N3u1R6uwQfuobCqbCgBkpsgBxvr1tZpe7B";
        Address actualAddress = scriptHashToP2sh.apply(hash, TESTNET3);
        assert expectedAddress.equals(actualAddress.value());
    }

    private void testPrivateKeyToP2pkhTestnetAddress1() {
        // Test params from Jimmy Song book, Chapter 4, Exercise 5 (use uncompressed SEC on testnet)
        Secp256k1PrivateKey privateKey = new Secp256k1PrivateKey(BigInteger.valueOf(5002));
        Secp256k1Point publicKey = privateKey.getPublicKey();
        Address actualAddress = publicKeyToP2pkhAddress.apply(publicKey, false, TESTNET3);
        String expectedAddress = "mmTPbXQFxboEtNRkwfh6K51jvdtHLxGeMA";
        assert expectedAddress.equals(actualAddress.value());
    }


    private void testPrivateKeyToP2pkhTestnetAddress2() {
        // Test params from Jimmy Song book, Chapter 4, Exercise 5 (use compressed SEC on testnet)
        BigInteger secret = BigInteger.valueOf(2020).pow(5);
        Secp256k1PrivateKey privateKey = new Secp256k1PrivateKey(secret);
        Secp256k1Point publicKey = privateKey.getPublicKey();
        Address actualAddress = publicKeyToP2pkhAddress.apply(publicKey, true, TESTNET3);
        String expectedAddress = "mopVkxp8UhXqRYbCYJsbeE1h1fiF64jcoH";
        assert expectedAddress.equals(actualAddress.value());
    }

    private void testPrivateKeyToP2pkhMainnetAddress1() {
        // Test params from Jimmy Song book, Chapter 4, Exercise 5 (use compressed SEC on mainnet)
        BigInteger secret = HEX.stringToBigInt.apply("0x12345deadbeef");
        Secp256k1PrivateKey privateKey = new Secp256k1PrivateKey(secret);
        Secp256k1Point publicKey = privateKey.getPublicKey();
        Address actualAddress = publicKeyToP2pkhAddress.apply(publicKey, true, MAINNET);
        String expectedAddress = "1F1Pn2y6pDb68E5nYJJeba4TLg2U7B6KF1";
        assert expectedAddress.equals(actualAddress.value());
        assert P2PKH.equals(actualAddress.addressType());
        assert MAINNET.equals(actualAddress.networkType());
    }
}
