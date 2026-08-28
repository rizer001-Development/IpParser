package dev.ipparser.gui;

import dev.ipparser.probe.McProbe;
import java.util.regex.Pattern;

/**
 * Pure, side-effect-free MC-probe log filter logic (no Swing dependencies),
 * extracted from the old monolithic window class so it can be unit tested.
 *
 * An invalid filter value never discards results: malformed numeric/version
 * values or invalid regexes are treated as "filter disabled".
 */
public final class McFilters {

    /** Operators available for online-count / version filters. */
    public static final String[] OPERATORS = {"is", "above", "below", "in-range", "out-of-range"};

    /** Mutable settings object read by worker threads (usually mutated on the EDT). */
    public static final class Settings {
        public boolean online;
        public String onlineOp = "is";
        public String onlineVal = "";

        public boolean version;
        public String versionOp = "is";
        public String versionVal = "";

        public boolean brand;
        public String brandVal = "";

        public boolean motd;
        public String motdVal = "";

        public boolean players;
        public String playersVal = "";
    }

    private McFilters() {
    }

    /**
     * Returns true if a successful MC probe passes all enabled filters.
     */
    public static boolean passes(McProbe.Result probe, Settings s) {
        if (s.online) {
            int[] range = parseNumRange(s.onlineVal);
            if (range != null && !numInRange(probe.online, s.onlineOp, range)) return false;
        }
        if (s.version && !s.versionVal.isBlank()) {
            if (!versionMatches(probe.version, s.versionOp, s.versionVal)) return false;
        }
        if (s.brand && !s.brandVal.isBlank()) {
            if (!regexFind(probe.brand, s.brandVal)) return false;
        }
        if (s.motd && !s.motdVal.isBlank()) {
            if (!regexFind(probe.motd, s.motdVal)) return false;
        }
        if (s.players && !s.playersVal.isBlank()) {
            boolean any = false;
            if (probe.players != null) {
                for (String name : probe.players) {
                    if (regexFind(name, s.playersVal)) {
                        any = true;
                        break;
                    }
                }
            }
            if (!any) return false;
        }
        return true;
    }

    /** Parses "5" or "10-30" into {lo, hi}; null if invalid. */
    public static int[] parseNumRange(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        if (t.contains("-")) {
            String[] p = t.split("-");
            if (p.length != 2) return null;
            try {
                int lo = Integer.parseInt(p[0].trim());
                int hi = Integer.parseInt(p[1].trim());
                return new int[]{Math.min(lo, hi), Math.max(lo, hi)};
            } catch (NumberFormatException e) {
                return null;
            }
        }
        try {
            int v = Integer.parseInt(t);
            return new int[]{v, v};
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Applies the operator: is / above / below / in-range / out-of-range against {lo, hi}. */
    public static boolean numInRange(int value, String op, int[] range) {
        switch (op) {
            case "is": return value == range[0];
            case "above": return value > range[1];
            case "below": return value < range[0];
            case "in-range": return value >= range[0] && value <= range[1];
            case "out-of-range": return value < range[0] || value > range[1];
            default: return true;
        }
    }

    /** Compares two MC version strings numerically, e.g. "1.21.1" vs "1.21.4". */
    public static int compareVersions(String a, String b) {
        int[] pa = versionParts(a);
        int[] pb = versionParts(b);
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int x = i < pa.length ? pa[i] : 0;
            int y = i < pb.length ? pb[i] : 0;
            if (x != y) return Integer.compare(x, y);
        }
        return 0;
    }

    /** Extracts numeric version parts from e.g. "1.21.1-SNAPSHOT" -> {1,21,1}. */
    public static int[] versionParts(String v) {
        if (v == null) return new int[0];
        StringBuilder digits = new StringBuilder();
        for (char c : v.trim().toCharArray()) {
            if (Character.isDigit(c) || c == '.') digits.append(c);
            else if (c == '-' || c == '+') digits.append('.');
        }
        String[] parts = digits.toString().split("\\.");
        java.util.List<Integer> list = new java.util.ArrayList<>();
        for (String p : parts) {
            if (!p.isEmpty()) {
                try {
                    list.add(Integer.parseInt(p));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        int[] res = new int[list.size()];
        for (int i = 0; i < res.length; i++) res[i] = list.get(i);
        return res;
    }

    /** Version operator check: is / above / below / in-range / out-of-range ("1.21.1-1.21.4"). */
    public static boolean versionMatches(String version, String op, String spec) {
        String s = spec.trim();
        if ("in-range".equals(op) || "out-of-range".equals(op)) {
            String[] p = s.split("-");
            if (p.length == 2) {
                int c1 = compareVersions(version, p[0].trim());
                int c2 = compareVersions(version, p[1].trim());
                boolean inside = c1 >= 0 && c2 <= 0;
                return "in-range".equals(op) ? inside : !inside;
            }
            if (p.length == 1) {
                // single value: out-of-range = any version except this one
                return "out-of-range".equals(op) && compareVersions(version, s) != 0;
            }
            // malformed multi-dash spec: filter disabled (never discard results)
            return true;
        }
        int c = compareVersions(version, s);
        switch (op) {
            case "is": return c == 0;
            case "above": return c > 0;
            case "below": return c < 0;
            default: return true;
        }
    }

    /**
     * True if the regex is found anywhere in text. An INVALID regex is treated
     * as "filter disabled" (returns true) so a typo never silently discards
     * scan results - consistent with invalid numeric filter values.
     */
    public static boolean regexFind(String text, String regex) {
        if (text == null || regex == null || regex.isBlank()) return false;
        try {
            return Pattern.compile(regex).matcher(text).find();
        } catch (Exception e) {
            return true; // invalid regex: don't filter
        }
    }
}