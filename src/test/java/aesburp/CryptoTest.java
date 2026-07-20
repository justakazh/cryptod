package aesburp;

/**
 * Standalone round-trip check for AesCrypto and Locator. No test framework:
 *   javac -cp lib/montoya-api.jar -d build src/main/.../*.java src/test/.../CryptoTest.java
 *   java  -cp lib/montoya-api.jar:build aesburp.CryptoTest
 */
public class CryptoTest {

    static int checks = 0;

    public static void main(String[] args) throws Exception {
        // 16-byte key/iv in hex for deterministic tests
        String keyHex = "000102030405060708090a0b0c0d0e0f";
        String ivHex = "0f0e0d0c0b0a09080706050403020100";
        String msg = "hello aes {\"user\":\"admin\"}";

        for (AesConfig.Encoding enc : AesConfig.Encoding.values()) {
            // CBC static IV
            roundTrip(cfg(AesConfig.Mode.CBC, keyHex, ivHex, false, enc), msg, "CBC/static/" + enc);
            // CBC prepended IV (random each time)
            roundTrip(cfg(AesConfig.Mode.CBC, keyHex, "", true, enc), msg, "CBC/prepend/" + enc);
            // GCM static nonce
            roundTrip(cfg(AesConfig.Mode.GCM, keyHex, "0f0e0d0c0b0a090807060504", false, enc), msg, "GCM/static/" + enc);
            // GCM prepended nonce
            roundTrip(cfg(AesConfig.Mode.GCM, keyHex, "", true, enc), msg, "GCM/prepend/" + enc);
            // ECB
            roundTrip(cfg(AesConfig.Mode.ECB, keyHex, "", false, enc), msg, "ECB/" + enc);
        }

        // Pretty: detection + reflow
        assertEq(true, Pretty.looksJson("{\"a\":1}"), "looksJson object");
        assertEq(false, Pretty.looksJson("a=1&b=2"), "looksJson form=false");
        assertEq(true, Pretty.looksForm("a=1&b=2"), "looksForm true");
        String pj = Pretty.prettyJson("{\"a\":1,\"b\":{\"c\":\"x,y:z\"}}");
        assertEq(true, pj.contains("\"x,y:z\""), "prettyJson preserves string with , and :");
        assertEq("{}", Pretty.prettyJson("{  }"), "prettyJson collapses empty object");

        System.out.println("OK - " + checks + " checks passed");
    }

    static AesConfig cfg(AesConfig.Mode mode, String keyHex, String ivHex, boolean prepend, AesConfig.Encoding enc) {
        AesConfig c = new AesConfig();
        c.mode = mode;
        c.key = keyHex;
        c.keyFormat = AesConfig.Fmt.HEX;
        c.iv = ivHex;
        c.ivFormat = AesConfig.Fmt.HEX;
        c.ivPrepended = prepend;
        c.encoding = enc;
        c.padding = AesConfig.Padding.PKCS5;
        return c;
    }

    static void roundTrip(AesConfig c, String msg, String label) throws Exception {
        AesCrypto crypto = new AesCrypto(c);
        String enc = crypto.encrypt(msg);
        String dec = crypto.decrypt(enc);
        assertEq(msg, dec, label);
    }

    static void assertEq(Object expected, Object actual, String label) {
        checks++;
        boolean ok = expected == null ? actual == null : expected.equals(actual);
        if (!ok) throw new AssertionError(label + ": expected [" + expected + "] got [" + actual + "]");
    }
}
