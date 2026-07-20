package aesburp;

import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Base64;

/**
 * AES encrypt/decrypt driven by a live AesConfig. Supports CBC, GCM, ECB with
 * Base64 / Base64-URL / Hex message encodings and a prepended-IV option.
 */
public class AesCrypto {

    private final AesConfig cfg;
    private final SecureRandom rng = new SecureRandom();

    public AesCrypto(AesConfig cfg) {
        this.cfg = cfg;
    }

    public String decrypt(String encoded) throws Exception {
        byte[] data = decode(encoded.trim());
        SecretKeySpec keySpec = new SecretKeySpec(bytes(cfg.key, cfg.keyFormat), "AES");

        switch (cfg.mode) {
            case GCM: {
                byte[] iv, ct;
                if (cfg.ivPrepended) {
                    iv = Arrays.copyOfRange(data, 0, cfg.gcmNonceLen);
                    ct = Arrays.copyOfRange(data, cfg.gcmNonceLen, data.length);
                } else {
                    iv = bytes(cfg.iv, cfg.ivFormat);
                    ct = data;
                }
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.DECRYPT_MODE, keySpec, new GCMParameterSpec(cfg.gcmTagBits, iv));
                return new String(c.doFinal(ct), StandardCharsets.UTF_8);
            }
            case CBC: {
                byte[] iv, ct;
                if (cfg.ivPrepended) {
                    iv = Arrays.copyOfRange(data, 0, 16);
                    ct = Arrays.copyOfRange(data, 16, data.length);
                } else {
                    iv = bytes(cfg.iv, cfg.ivFormat);
                    ct = data;
                }
                Cipher c = Cipher.getInstance("AES/CBC/" + pad());
                c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
                return new String(c.doFinal(ct), StandardCharsets.UTF_8);
            }
            default: { // ECB
                Cipher c = Cipher.getInstance("AES/ECB/" + pad());
                c.init(Cipher.DECRYPT_MODE, keySpec);
                return new String(c.doFinal(data), StandardCharsets.UTF_8);
            }
        }
    }

    public String encrypt(String plaintext) throws Exception {
        byte[] pt = plaintext.getBytes(StandardCharsets.UTF_8);
        SecretKeySpec keySpec = new SecretKeySpec(bytes(cfg.key, cfg.keyFormat), "AES");

        switch (cfg.mode) {
            case GCM: {
                byte[] iv = ivForEncrypt(cfg.gcmNonceLen);
                Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
                c.init(Cipher.ENCRYPT_MODE, keySpec, new GCMParameterSpec(cfg.gcmTagBits, iv));
                byte[] ct = c.doFinal(pt);
                return encode(cfg.ivPrepended ? concat(iv, ct) : ct);
            }
            case CBC: {
                byte[] iv = ivForEncrypt(16);
                Cipher c = Cipher.getInstance("AES/CBC/" + pad());
                c.init(Cipher.ENCRYPT_MODE, keySpec, new IvParameterSpec(iv));
                byte[] ct = c.doFinal(pt);
                return encode(cfg.ivPrepended ? concat(iv, ct) : ct);
            }
            default: { // ECB
                Cipher c = Cipher.getInstance("AES/ECB/" + pad());
                c.init(Cipher.ENCRYPT_MODE, keySpec);
                return encode(c.doFinal(pt));
            }
        }
    }

    private String pad() {
        return cfg.padding == AesConfig.Padding.NONE ? "NoPadding" : "PKCS5Padding";
    }

    /** Use the static IV if provided; otherwise a fresh random one (prepended mode). */
    private byte[] ivForEncrypt(int len) {
        byte[] iv = bytes(cfg.iv, cfg.ivFormat);
        if (iv.length > 0) return iv;
        byte[] r = new byte[len];
        rng.nextBytes(r);
        return r;
    }

    // --- encoding helpers ---

    private byte[] decode(String s) {
        switch (cfg.encoding) {
            case HEX: return hexDecode(s);
            case BASE64URL: return Base64.getUrlDecoder().decode(s);
            default: return Base64.getMimeDecoder().decode(s);
        }
    }

    private String encode(byte[] b) {
        switch (cfg.encoding) {
            case HEX: return hexEncode(b);
            case BASE64URL: return Base64.getUrlEncoder().withoutPadding().encodeToString(b);
            default: return Base64.getEncoder().encodeToString(b);
        }
    }

    static byte[] bytes(String s, AesConfig.Fmt fmt) {
        if (s == null) return new byte[0];
        switch (fmt) {
            case HEX: return hexDecode(s.trim());
            case BASE64: return Base64.getMimeDecoder().decode(s.trim());
            default: return s.getBytes(StandardCharsets.UTF_8);
        }
    }

    static byte[] concat(byte[] a, byte[] b) {
        byte[] out = new byte[a.length + b.length];
        System.arraycopy(a, 0, out, 0, a.length);
        System.arraycopy(b, 0, out, a.length, b.length);
        return out;
    }

    static byte[] hexDecode(String s) {
        s = s.replaceAll("\\s", "");
        int n = s.length();
        byte[] out = new byte[n / 2];
        for (int i = 0; i < n; i += 2) {
            out[i / 2] = (byte) Integer.parseInt(s.substring(i, i + 2), 16);
        }
        return out;
    }

    static String hexEncode(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}
