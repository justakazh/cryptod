package aesburp;

/**
 * Lightweight, dependency-free detection + JSON pretty-printer. Best-effort:
 * prettyJson only reflows structure and never validates, so malformed input
 * comes back reflowed rather than rejected. Callers gate it with looksJson.
 */
public class Pretty {

    public static boolean looksJson(String s) {
        String t = s.trim();
        return (t.startsWith("{") && t.endsWith("}")) || (t.startsWith("[") && t.endsWith("]"));
    }

    /** key=value(&key=value)* with no JSON-ish opening. */
    public static boolean looksForm(String s) {
        String t = s.trim();
        if (t.isEmpty() || t.startsWith("{") || t.startsWith("[")) return false;
        if (t.indexOf('=') < 0) return false;
        for (String part : t.split("&")) {
            if (part.indexOf('=') < 0) return false;
        }
        return true;
    }

    /** Indent JSON by two spaces per level, respecting string literals and escapes. */
    public static String prettyJson(String s) {
        String t = s.trim();
        StringBuilder sb = new StringBuilder(t.length() + 64);
        int indent = 0;
        boolean inStr = false, esc = false;
        for (int i = 0; i < t.length(); i++) {
            char ch = t.charAt(i);
            if (inStr) {
                sb.append(ch);
                if (esc) esc = false;
                else if (ch == '\\') esc = true;
                else if (ch == '"') inStr = false;
                continue;
            }
            switch (ch) {
                case '"':
                    inStr = true;
                    sb.append(ch);
                    break;
                case '{':
                case '[': {
                    int j = i + 1;
                    while (j < t.length() && Character.isWhitespace(t.charAt(j))) j++;
                    if (j < t.length() && (t.charAt(j) == '}' || t.charAt(j) == ']')) {
                        sb.append(ch).append(t.charAt(j)); // collapse {} / []
                        i = j;
                    } else {
                        indent++;
                        sb.append(ch).append('\n').append(pad(indent));
                    }
                    break;
                }
                case '}':
                case ']':
                    indent = Math.max(0, indent - 1);
                    sb.append('\n').append(pad(indent)).append(ch);
                    break;
                case ',':
                    sb.append(ch).append('\n').append(pad(indent));
                    break;
                case ':':
                    sb.append(": ");
                    break;
                default:
                    if (!Character.isWhitespace(ch)) sb.append(ch);
            }
        }
        return sb.toString();
    }

    private static String pad(int n) {
        return "  ".repeat(n);
    }
}
