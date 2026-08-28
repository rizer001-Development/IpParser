package dev.ipparser.pattern;

/**
 * Converts the user's IP syntax input (Type: ip / wildcard / regex) into the
 * internal Java-regex form consumed by {@link IpPattern}, honouring the
 * "Use CIDR" setting.
 *
 * Type  ip       - a full IP, e.g. "95.31.158.9". With CIDR: "95.31.158.9/24".
 * Type  wildcard - wildcard octets, e.g. "95.31.***.*"  (* = any number).
 *                  With CIDR: "95.31.***.* / 8" (wildcard octets become 0 in
 *                  the network base, the prefix defines the range).
 * Type  regex    - a plain Java regex (or regex + CIDR block inside the regex).
 *
 * Returns the internal regex string, or null if the input is invalid for the
 * selected type / CIDR setting.
 */
public final class SyntaxConv {

    private SyntaxConv() {
    }

    /** Converts one input line to the internal regex form; null if invalid. */
    public static String toRegex(String raw, String type, boolean useCidr) {
        if (raw == null) return null;
        String s = raw.trim();
        if (s.isEmpty()) return null;
        if ("ip".equals(type)) {
            return ipToRegex(s, useCidr);
        }
        if ("wildcard".equals(type)) {
            return wildcardToRegex(s, useCidr);
        }
        return s; // regex type: pass through, IpPattern applies the CIDR flag
    }

    // ---------- Type: ip ----------

    private static String ipToRegex(String s, boolean useCidr) {
        String[] baseAndPrefix = splitCidr(s, useCidr);
        if (baseAndPrefix == null) return null;
        String base = baseAndPrefix[0];
        if (!isLiteralIp(base)) return null;
        String escaped = base.replace(".", "\\.");
        if (baseAndPrefix[1] != null) {
            if (!validPrefix(baseAndPrefix[1])) return null;
            return escaped + "/" + baseAndPrefix[1];
        }
        return escaped;
    }

    private static boolean isLiteralIp(String s) {
        if (!s.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) return false;
        for (String o : s.split("\\.")) {
            try {
                if (Integer.parseInt(o) > 255) return false;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return true;
    }

    // ---------- Type: wildcard ----------

    private static String wildcardToRegex(String s, boolean useCidr) {
        String[] baseAndPrefix = splitCidr(s, useCidr);
        if (baseAndPrefix == null) return null;
        String base = baseAndPrefix[0];
        String[] octets = base.split("\\.");
        if (octets.length != 4) return null;

        String[] parts = new String[4];
        for (int i = 0; i < 4; i++) {
            parts[i] = wildcardOctet(octets[i]);
            if (parts[i] == null) return null;
        }

        if (baseAndPrefix[1] != null) {
            // CIDR over a wildcard base: wildcard octets become 0 in the network
            // base (e.g. 95.31.***.* slash 8 -> 95.31.0.0 slash 8), prefix defines the range.
            if (!validPrefix(baseAndPrefix[1])) return null;
            String[] numericBase = new String[4];
            for (int i = 0; i < 4; i++) {
                numericBase[i] = octets[i].matches("\\d+") ? octets[i] : "0";
            }
            return String.join(".", numericBase).replace(".", "\\.") + "/" + baseAndPrefix[1];
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 4; i++) {
            if (i > 0) sb.append("\\.");
            sb.append(parts[i]);
        }
        return sb.toString();
    }

    /**
     * One wildcard octet -> regex part, or null if invalid.
     * "192" -> "192"; "*" or "***" -> any 0-255 value; "1*0" -> "1\\d0";
     * "25*" -> "25\\d". Digits and '*' only.
     */
    private static String wildcardOctet(String o) {
        if (o == null || o.isEmpty() || !o.matches("[0-9*]+")) return null;
        if (o.indexOf('*') < 0) {
            try {
                if (Integer.parseInt(o) > 255) return null;
            } catch (NumberFormatException e) {
                return null;
            }
            return o;
        }
        // all-stars octet: any 0-255 value
        if (o.replace("*", "").isEmpty()) return "\\d{1,3}";
        // mixed digits + stars: each * = one digit position
        StringBuilder sb = new StringBuilder();
        for (char c : o.toCharArray()) {
            if (c == '*') sb.append("\\d");
            else sb.append(c);
        }
        return sb.toString();
    }

    // ---------- shared ----------

    /**
     * Splits "base/prefix" when CIDR is enabled. Returns {base, prefix} or
     * {s, null} when there is no prefix. Returns null when CIDR is disabled and
     * the input contains a '/'.
     */
    private static String[] splitCidr(String s, boolean useCidr) {
        int slash = s.indexOf('/');
        if (slash < 0) {
            return new String[]{s, null};
        }
        if (!useCidr) return null; // '/' is not allowed when CIDR is off
        String base = s.substring(0, slash).trim();
        String prefix = s.substring(slash + 1).trim();
        if (base.isEmpty() || prefix.isEmpty()) return null;
        return new String[]{base, prefix};
    }

    private static boolean validPrefix(String p) {
        try {
            int v = Integer.parseInt(p);
            return v >= 0 && v <= 32;
        } catch (NumberFormatException e) {
            return false;
        }
    }
}