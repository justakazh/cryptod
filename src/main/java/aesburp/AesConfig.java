package aesburp;

import burp.api.montoya.persistence.Preferences;

/**
 * Holds all AES settings. Backed by Burp preferences so values survive restarts.
 */
public class AesConfig {

    public enum Fmt { UTF8, HEX, BASE64 }
    public enum Mode { CBC, GCM, ECB }
    public enum Padding { PKCS5, NONE }
    public enum Encoding { BASE64, BASE64URL, HEX }

    public String key = "";
    public Fmt keyFormat = Fmt.UTF8;
    public Mode mode = Mode.CBC;
    public Padding padding = Padding.PKCS5;
    public String iv = "";
    public Fmt ivFormat = Fmt.UTF8;
    public boolean ivPrepended = false;
    public int gcmTagBits = 128;
    public int gcmNonceLen = 12;
    public Encoding encoding = Encoding.BASE64;

    /** True once a key has been entered (minimum needed to attempt crypto). */
    public boolean isReady() {
        return key != null && !key.isEmpty();
    }

    public void load(Preferences p) {
        key = orDefault(p.getString("aes.key"), key);
        keyFormat = enumOr(p.getString("aes.keyFormat"), Fmt.class, keyFormat);
        mode = enumOr(p.getString("aes.mode"), Mode.class, mode);
        padding = enumOr(p.getString("aes.padding"), Padding.class, padding);
        iv = orDefault(p.getString("aes.iv"), iv);
        ivFormat = enumOr(p.getString("aes.ivFormat"), Fmt.class, ivFormat);
        Boolean bp = p.getBoolean("aes.ivPrepended");
        if (bp != null) ivPrepended = bp;
        Integer tag = p.getInteger("aes.gcmTagBits");
        if (tag != null) gcmTagBits = tag;
        Integer nl = p.getInteger("aes.gcmNonceLen");
        if (nl != null) gcmNonceLen = nl;
        encoding = enumOr(p.getString("aes.encoding"), Encoding.class, encoding);
    }

    public void save(Preferences p) {
        p.setString("aes.key", key);
        p.setString("aes.keyFormat", keyFormat.name());
        p.setString("aes.mode", mode.name());
        p.setString("aes.padding", padding.name());
        p.setString("aes.iv", iv);
        p.setString("aes.ivFormat", ivFormat.name());
        p.setBoolean("aes.ivPrepended", ivPrepended);
        p.setInteger("aes.gcmTagBits", gcmTagBits);
        p.setInteger("aes.gcmNonceLen", gcmNonceLen);
        p.setString("aes.encoding", encoding.name());
    }

    private static String orDefault(String v, String def) {
        return v == null ? def : v;
    }

    private static <E extends Enum<E>> E enumOr(String v, Class<E> type, E def) {
        if (v == null) return def;
        try {
            return Enum.valueOf(type, v);
        } catch (IllegalArgumentException e) {
            return def;
        }
    }
}
