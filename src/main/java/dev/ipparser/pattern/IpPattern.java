package dev.ipparser.pattern;

import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

/**
 * Expands a Java regex (which may contain CIDR blocks) into all concrete IPv4
 * addresses.
 *
 * The syntax field accepts a Java regex describing IPv4 addresses: 4 octets
 * (each 0-255) separated by dots. CIDR blocks can be written INSIDE the regex,
 * with regex-escaped dots (95\\.31\\.0\\.0/16) or plain dots (95.31.0.0/16), and
 * several ranges can be combined with top-level "|" alternation.
 * Anchors (^ and $) at the very ends are optional. There is NO limit on the
 * number of generated addresses.
 *
 * Examples:
 *   "95\\.31\\.\\d{1,3}\\.\\d"            → third octet 0-255, fourth 0-9   (2560 IPs)
 *   "95\\.31\\.0\\.0/16"                → 95.31.0.0 … 95.31.255.255       (65536 IPs)
 *   "95.31.0.0/16"                   → same block, plain-dot CIDR       (65536 IPs)
 *   "^192\\.168\\.1\\.0/24$"            → 192.168.1.0 … 192.168.1.255     (256 IPs)
 *   "95\\.31\\.0\\.0/16|10\\.0\\.0\\.0/8"  → both blocks combined            (16.8M IPs)
 *   "192\\.168\\.1\\.\\d"                → 192.168.1.0 … 192.168.1.9       (10 IPs)
 *   "172\\.16\\.1\\d\\d\\.1"              → 172.16.100.1 … 172.16.199.1     (100 IPs)
 */
public final class IpPattern {

    private IpPattern() {
    }

    /**
     * Splits a regex into top-level "|" alternatives (outside groups and
     * character classes). Used so CIDR blocks can be combined with alternation.
     */
    static List<String> splitTopLevelAlternation(String s) {
        List<String> parts = new ArrayList<>();
        StringBuilder cur = new StringBuilder();
        int depth = 0;
        boolean inClass = false;
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') {
                cur.append(c);
                if (i + 1 < s.length()) {
                    cur.append(s.charAt(i + 1));
                    i++;
                }
                continue;
            }
            if (c == '[') {
                inClass = true;
            } else if (c == ']') {
                inClass = false;
            }
            if (!inClass) {
                if (c == '(') {
                    depth++;
                } else if (c == ')') {
                    depth--;
                } else if (c == '|' && depth == 0) {
                    parts.add(cur.toString());
                    cur.setLength(0);
                    continue;
                }
            }
            cur.append(c);
        }
        parts.add(cur.toString());
        return parts;
    }

    /**
     * Finds the index of the paren that closes the group opened at {@code open}.
     * Returns -1 if unbalanced. Skips escaped chars and character classes.
     */
    private static int matchingParen(String s, int open) {
        int depth = 0;
        boolean inClass = false;
        for (int i = open; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\') {
                i++;
                continue;
            }
            if (c == '[') {
                inClass = true;
                continue;
            }
            if (c == ']') {
                inClass = false;
                continue;
            }
            if (inClass) continue;
            if (c == '(') {
                depth++;
            } else if (c == ')') {
                depth--;
                if (depth == 0) return i;
            }
        }
        return -1;
    }

    /**
     * Unwraps a single enclosing group if it wraps the WHOLE string
     * (e.g. "(?:95\\.31\\.0\\.0/16|10\\.0\\.0\\.0/8)" -> the inner alternation).
     */
    private static String unwrapOuterGroup(String s) {
        String t = s.trim();
        if (t.length() >= 2 && t.charAt(0) == '(') {
            int close = matchingParen(t, 0);
            if (close == t.length() - 1) {
                int openerLen = t.startsWith("(?:") ? 3 : 1;
                return t.substring(openerLen, close).trim();
            }
        }
        return t;
    }

    /** Strips optional leading ^ and trailing $ anchors, then trims. */
    private static String stripAnchors(String a) {
        String c = a;
        if (c.startsWith("^")) c = c.substring(1);
        if (c.endsWith("$")) c = c.substring(0, c.length() - 1);
        return c.trim();
    }

    /**
     * Parses the input into a list of address blocks. Each block is 4 octet
     * value lists. Returns an empty list if the whole input is invalid.
     * CIDR interpretation enabled.
     */
    public static List<List<List<Integer>>> blocks(String input) {
        return blocks(input, true);
    }

    /**
     * Parses the input into address blocks. When {@code allowCidr} is false,
     * a "…/prefix" suffix is NOT treated as a CIDR block and the whole string
     * must be a plain octet regex.
     */
    public static List<List<List<Integer>>> blocks(String input, boolean allowCidr) {
        List<List<List<Integer>>> result = new ArrayList<>();
        if (input == null) return result;
        String t = input.trim();
        if (t.isEmpty()) return result;
        t = unwrapOuterGroup(t);
        List<String> alts = splitTopLevelAlternation(t);
        for (String alt : alts) {
            String a = alt.trim();
            if (a.isEmpty()) {
                result.clear();
                return result;
            }
            String core = stripAnchors(a);
            List<List<Integer>> block = allowCidr ? tryCidr(core) : null;
            if (block == null) {
                block = octetValues(core);
            }
            if (block == null) {
                result.clear();
                return result;
            }
            result.add(block);
        }
        return result;
    }

    /** Returns the octet value lists for a CIDR block string, or null if it is not a valid CIDR. */
    private static List<List<Integer>> tryCidr(String s) {
        if (s == null || s.isEmpty()) return null;
        String norm = s.replace("\\.", ".");
        int slash = norm.indexOf('/');
        if (slash <= 0) return null;
        String base = norm.substring(0, slash).trim();
        String prefStr = norm.substring(slash + 1).trim();
        if (!base.matches("\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}\\.\\d{1,3}")) return null;
        String[] octs = base.split("\\.");
        int[] baseOct = new int[4];
        for (int i = 0; i < 4; i++) {
            try {
                baseOct[i] = Integer.parseInt(octs[i]);
            } catch (NumberFormatException e) {
                return null;
            }
            if (baseOct[i] < 0 || baseOct[i] > 255) return null;
        }
        int prefix;
        try {
            prefix = Integer.parseInt(prefStr);
        } catch (NumberFormatException e) {
            return null;
        }
        if (prefix < 0 || prefix > 32) return null;
        return octetListsFromCidr(baseOct, prefix);
    }

    /**
     * Builds the four octet value lists for a CIDR block (e.g. "95.31.0.0/16").
     * Because CIDR blocks are power-of-two aligned, each octet ranges over an
     * independent interval and the product equals the block size.
     */
    private static List<List<Integer>> octetListsFromCidr(int[] base, int prefix) {
        long ip = ((long) base[0] << 24) | ((long) base[1] << 16) | ((long) base[2] << 8) | base[3];
        long mask = prefix == 0 ? 0 : (0xFFFFFFFFL << (32 - prefix)) & 0xFFFFFFFFL;
        long start = ip & mask;
        long end = start | ((0xFFFFFFFFL & ~mask) & 0xFFFFFFFFL);

        List<List<Integer>> octetLists = new ArrayList<>(4);
        for (int i = 0; i < 4; i++) {
            int shift = 8 * (3 - i);
            int lo = (int) ((start >> shift) & 0xFF);
            int hi = (int) ((end >> shift) & 0xFF);
            List<Integer> vals = new ArrayList<>(hi - lo + 1);
            for (int v = lo; v <= hi; v++) {
                vals.add(v);
            }
            octetLists.add(vals);
        }
        return octetLists;
    }

    /**
     * Number of IPv4 addresses the syntax matches, computed WITHOUT building the
     * list (used by the live scale indicator). Returns 0 if the syntax is
     * invalid or matches nothing. CIDR interpretation enabled.
     */
    public static long countIps(String input) {
        return countIps(input, true);
    }

    /** countIps with an explicit CIDR flag. */
    public static long countIps(String input, boolean allowCidr) {
        List<List<List<Integer>>> bs = blocks(input, allowCidr);
        if (bs.isEmpty()) return 0;
        long total = 0;
        for (List<List<Integer>> b : bs) {
            long p = 1;
            for (List<Integer> list : b) {
                p *= list.size();
            }
            total += p;
        }
        return total;
    }

    // ================= MULTI-PATTERN (list / file modes) =================

    /**
     * Combines several pattern lines (each a regex/CIDR syntax, one per line)
     * into a single list of address blocks. Blank lines are skipped.
     * Returns an empty list if any non-blank line is invalid.
     * CIDR interpretation enabled.
     */
    public static List<List<List<Integer>>> blocksAll(List<String> lines) {
        return blocksAll(lines, true);
    }

    /** blocksAll with an explicit CIDR flag. */
    public static List<List<List<Integer>>> blocksAll(List<String> lines, boolean allowCidr) {
        List<List<List<Integer>>> all = new ArrayList<>();
        if (lines == null) return all;
        for (String line : lines) {
            String t = line == null ? "" : line.trim();
            if (t.isEmpty()) continue;
            List<List<List<Integer>>> b = blocks(t, allowCidr);
            if (b.isEmpty()) {
                all.clear();
                return all;
            }
            all.addAll(b);
        }
        return all;
    }

    /** Total IP count across all pattern lines (blank lines skipped). */
    public static long countIpsAll(List<String> lines) {
        return countIpsAll(lines, true);
    }

    /** countIpsAll with an explicit CIDR flag. */
    public static long countIpsAll(List<String> lines, boolean allowCidr) {
        List<List<List<Integer>>> all = blocksAll(lines, allowCidr);
        if (all.isEmpty()) return 0;
        long total = 0;
        for (List<List<Integer>> b : all) {
            long p = 1;
            for (List<Integer> list : b) p *= list.size();
            total += p;
        }
        return total;
    }

    /** Structural check across all pattern lines; blank lines skipped. */
    public static boolean structureOkAll(List<String> lines) {
        return structureOkAll(lines, true);
    }

    /** structureOkAll with an explicit CIDR flag. */
    public static boolean structureOkAll(List<String> lines, boolean allowCidr) {
        if (lines == null) return false;
        boolean any = false;
        for (String line : lines) {
            String t = line == null ? "" : line.trim();
            if (t.isEmpty()) continue;
            any = true;
            if (!structureOk(t, allowCidr)) return false;
        }
        return any;
    }

    /**
     * Structural check only (used to pick the right error message): every
     * top-level alternative must be a valid CIDR or a regex with 4 compilable
     * octet parts. Does NOT require that the parts match any 0-255 value.
     * CIDR interpretation enabled.
     */
    public static boolean structureOk(String input) {
        return structureOk(input, true);
    }

    /** structureOk with an explicit CIDR flag. */
    public static boolean structureOk(String input, boolean allowCidr) {
        if (input == null || input.trim().isEmpty()) return false;
        String t = unwrapOuterGroup(input.trim());
        List<String> alts = splitTopLevelAlternation(t);
        for (String alt : alts) {
            String a = alt.trim();
            if (a.isEmpty()) return false;
            String core = stripAnchors(a);
            if (allowCidr && tryCidr(core) != null) continue;
            if (core.contains("/")) return false; // malformed CIDR-looking input
            List<String> parts = splitOctets(core);
            if (parts.size() != 4) return false;
            parts.set(0, parts.get(0).replaceFirst("^\\^", ""));
            parts.set(3, parts.get(3).replaceFirst("\\$$", ""));
            for (String part : parts) {
                if (part.isEmpty()) return false;
                try {
                    Pattern.compile("^(?:" + part + ")$");
                } catch (Exception ex) {
                    return false;
                }
            }
        }
        return true;
    }

    /** Expands the syntax into all matching IPv4 strings (used by tests/tools). */
    public static List<String> expand(String input) {
        List<List<List<Integer>>> bs = blocks(input);
        if (bs.isEmpty()) return new ArrayList<>();
        List<String> result = new ArrayList<>();
        for (List<List<Integer>> block : bs) {
            for (int a : block.get(0)) {
                for (int b : block.get(1)) {
                    for (int c : block.get(2)) {
                        for (int d : block.get(3)) {
                            result.add(a + "." + b + "." + c + "." + d);
                        }
                    }
                }
            }
        }
        return result;
    }

    /**
     * Returns the four octet value lists for a regex, or null if it is invalid
     * or matches no 0-255 values.
     */
    private static List<List<Integer>> octetValues(String regex) {
        if (regex == null || regex.trim().isEmpty()) {
            return null;
        }
        String r = regex.trim();
        try {
            Pattern.compile(r);
        } catch (Exception ex) {
            return null;
        }

        List<String> parts = splitOctets(r);
        if (parts.size() != 4) {
            return null;
        }
        parts.set(0, parts.get(0).replaceFirst("^\\^", ""));
        parts.set(3, parts.get(3).replaceFirst("\\$$", ""));

        List<List<Integer>> octetValues = new ArrayList<>(4);
        for (int i = 0; i < 4; i++) {
            String part = parts.get(i);
            if (part.isEmpty()) {
                return null;
            }
            Pattern octetPattern;
            try {
                octetPattern = Pattern.compile("^(?:" + part + ")$");
            } catch (Exception ex) {
                return null;
            }
            List<Integer> values = new ArrayList<>();
            for (int v = 0; v <= 255; v++) {
                if (octetPattern.matcher(String.valueOf(v)).matches()) {
                    values.add(v);
                }
            }
            if (values.isEmpty()) {
                return null;
            }
            octetValues.add(values);
        }
        return octetValues;
    }

    /**
     * Splits a regex into octet parts on unescaped dots that are outside
     * character classes. Handles both \\. and . separators.
     */
    static List<String> splitOctets(String regex) {
        List<String> parts = new ArrayList<>();
        StringBuilder current = new StringBuilder();
        boolean inClass = false;

        for (int i = 0; i < regex.length(); i++) {
            char c = regex.charAt(i);
            if (c == '\\') {
                if (i + 1 < regex.length()) {
                    char next = regex.charAt(i + 1);
                    if (!inClass && next == '.') {
                        parts.add(current.toString());
                        current.setLength(0);
                        i++;
                        continue;
                    }
                    current.append(c).append(next);
                    i++;
                } else {
                    current.append(c);
                }
            } else if (c == '[') {
                inClass = true;
                current.append(c);
            } else if (c == ']') {
                inClass = false;
                current.append(c);
            } else if (c == '.' && !inClass) {
                parts.add(current.toString());
                current.setLength(0);
            } else {
                current.append(c);
            }
        }
        parts.add(current.toString());
        return parts;
    }
}