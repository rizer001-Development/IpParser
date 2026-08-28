package dev.ipparser.probe;

import dev.ipparser.core.PerfMonitor;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

/**
 * Minecraft Server List Ping (protocol). Connects to a Minecraft server
 * and retrieves real server info: MOTD, version, online/max players, latency.
 * Pure standard JDK, no external libraries.
 */
public final class McProbe {

    /** Result of a Minecraft ping. */
    public static class Result {
        public boolean success;
        public String motd = "";
        public String version = "";
        public int protocol;
        public int online;
        public int max;
        public boolean hasFavicon;
        public long latencyMs;
        public String error = "";
        public String brand = "";          // server brand, e.g. "Leaf", "Paper", "Vanilla"
        public List<String> players = new ArrayList<>(); // player sample names (if any)
    }

    private McProbe() {
    }

    /**
     * Pings a Minecraft server.
     * @param host IP or hostname
     * @param port server port (usually 25565)
     * @param timeoutMs connect/read timeout
     */
    public static Result ping(String host, int port, int timeoutMs) {
        Result r = new Result();
        long start = System.currentTimeMillis();
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            socket.setTcpNoDelay(true);

            DataOutputStream out = new DataOutputStream(socket.getOutputStream());
            DataInputStream in = new DataInputStream(socket.getInputStream());

            // ---- Handshake packet: id 0x00, protocol -1, host, port, next state 1 ----
            ByteArrayOutputStream payload = new ByteArrayOutputStream();
            DataOutputStream pkt = new DataOutputStream(payload);
            writeVarInt(pkt, 0x00);            // packet id
            writeVarInt(pkt, -1);              // protocol version (legacy client = -1)
            byte[] hostBytes = host.getBytes(StandardCharsets.UTF_8);
            writeVarInt(pkt, hostBytes.length);
            pkt.write(hostBytes);
            pkt.writeShort(port);
            writeVarInt(pkt, 1);               // next state: status

            byte[] body = payload.toByteArray();
            ByteArrayOutputStream packet = new ByteArrayOutputStream();
            DataOutputStream packetOut = new DataOutputStream(packet);
            writeVarInt(packetOut, body.length);
            packetOut.write(body);
            byte[] handshake = packet.toByteArray();
            out.write(handshake);
            out.flush();
            PerfMonitor.addSent(handshake.length);

            // ---- Status request: packet id 0x00 ----
            ByteArrayOutputStream req = new ByteArrayOutputStream();
            DataOutputStream reqOut = new DataOutputStream(req);
            writeVarInt(reqOut, 1);            // packet length
            writeVarInt(reqOut, 0x00);         // packet id
            byte[] reqBytes = req.toByteArray();
            out.write(reqBytes);
            out.flush();
            PerfMonitor.addSent(reqBytes.length);

            // ---- Read response ----
            int packetLen = readVarInt(in);
            byte[] response = new byte[packetLen];
            in.readFully(response);
            PerfMonitor.addRecv(packetLen + varIntLen(packetLen));

            DataInputStream resp = new DataInputStream(new ByteArrayInputStream(response));
            int packetId = readVarInt(resp);
            if (packetId != 0x00) {
                r.error = "неожиданный пакет (id " + packetId + ")";
                return r;
            }
            int jsonLen = readVarInt(resp);
            if (jsonLen < 0 || jsonLen > 2_000_000) {
                r.error = "некорректная длина ответа";
                return r;
            }
            byte[] jsonBytes = new byte[jsonLen];
            resp.readFully(jsonBytes);
            String json = new String(jsonBytes, StandardCharsets.UTF_8);

            r.latencyMs = System.currentTimeMillis() - start;
            r.success = true;
            parseJson(json, r);
        } catch (IOException e) {
            r.latencyMs = System.currentTimeMillis() - start;
            String msg = e.getMessage() != null ? e.getMessage().toLowerCase() : "";
            if (msg.contains("timed out") || msg.contains("timeout")) {
                r.error = "таймаут";
            } else {
                r.error = e.getClass().getSimpleName() + ": " + (e.getMessage() != null ? e.getMessage() : "");
            }
        }
        return r;
    }

    /**
     * Simple manual extraction of known fields from the status JSON.
     * Uses indexOf-based scanning (no regex) so huge base64 favicons cannot
     * blow the stack. No JSON library required.
     */
    private static void parseJson(String json, Result r) {
        String version = extractObjectString(json, "version", "name");
        if (version != null) r.version = unescape(version);
        r.protocol = extractInt(json, "protocol");
        r.online = extractInt(json, "online");
        r.max = extractInt(json, "max");

        // MOTD: "description" can be a plain string, {"text":"..."} or
        // {"extra":[{"text":"..."},...],"text":""}
        String motd = extractDescription(json);
        if (motd != null && !motd.isEmpty()) {
            r.motd = stripColorCodes(unescape(motd));
        }

        r.hasFavicon = json.contains("\"favicon\"");

        // brand: some servers report it as a top-level "brand":"Leaf" string
        String brand = extractTopLevelString(json, "brand");
        if (brand != null && !brand.isEmpty()) {
            r.brand = unescape(brand);
        }

        // player sample: "players":{"max":..,"online":..,"sample":[{"name":"..","id":".."}]}
        r.players = extractPlayerNames(json);

        // Many servers report the version as "Paper 1.21.1" / "Spigot 1.20.4".
        // Split the leading brand off so the version filter compares "1.21.1"
        // and the brand filter sees "Paper" (even without a top-level "brand" field).
        splitVersionBrand(r);
    }

    /** Known server software names used as prefixes in version strings. */
    private static final String[] KNOWN_BRANDS = {
            "paper", "purpur", "spigot", "craftbukkit", "bukkit", "vanilla", "fabric",
            "forge", "neoforge", "fml", "leaves", "leaf", "folia", "pufferfish",
            "velocity", "bungeecord", "waterfall", "arclight", "mohist", "catserver",
            "magma", "yatopia", "tuinity", "flamepaper", "sportpaper", "panda", "gale",
            "quilt", "krypton", "crucible", "diamondfire"
    };

    /**
     * Splits a combined version string like "Paper 1.21.1" into
     * brand="Paper" and version="1.21.1". If the server already reported a
     * top-level "brand", it is also stripped from the version prefix.
     * Pure version strings ("1.21.1") are left untouched.
     */
    private static void splitVersionBrand(Result r) {
        String v = r.version;
        if (v == null || v.isEmpty()) return;
        String vLower = v.toLowerCase();

        // 1) top-level brand known: strip its prefix from the version
        if (!r.brand.isEmpty() && v.length() >= r.brand.length()
                && vLower.startsWith(r.brand.toLowerCase())) {
            String rest = v.substring(r.brand.length()).trim();
            if (!rest.isEmpty() && Character.isDigit(rest.charAt(0))) {
                r.version = rest;
                return;
            }
        }
        // 2) known brand prefixes
        for (String b : KNOWN_BRANDS) {
            if (vLower.startsWith(b)) {
                String rest = v.substring(b.length()).trim();
                if (!rest.isEmpty() && Character.isDigit(rest.charAt(0))) {
                    r.brand = v.substring(0, b.length()).trim();
                    r.version = rest;
                    return;
                }
            }
        }
        // 3) generic fallback: a single leading word before the first digit
        int firstDigit = -1;
        for (int i = 0; i < v.length(); i++) {
            if (Character.isDigit(v.charAt(i))) { firstDigit = i; break; }
        }
        if (firstDigit > 0) {
            String lead = v.substring(0, firstDigit).trim();
            if (!lead.isEmpty() && lead.indexOf(' ') < 0) {
                r.brand = lead;
                r.version = v.substring(firstDigit).trim();
            }
        }
    }

    /** Extracts a top-level string value: {"brand":"Leaf"}. Returns null if absent. */
    private static String extractTopLevelString(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return null;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return null;
        int q = skipWhitespace(json, colon + 1);
        if (q >= json.length() || json.charAt(q) != '"') return null;
        return extractQuoted(json, q);
    }

    /** Extracts the player sample names: [{"name":"Steve","id":".."},...]. */
    private static List<String> extractPlayerNames(String json) {
        List<String> names = new ArrayList<>();
        int samp = json.indexOf("\"sample\"");
        if (samp < 0) return names;
        int colon = json.indexOf(':', samp);
        if (colon < 0) return names;
        int arr = skipWhitespace(json, colon + 1);
        if (arr >= json.length() || json.charAt(arr) != '[') return names;
        int close = findMatchingBracket(json, arr);
        if (close < 0) return names;
        String inner = json.substring(arr, close + 1);
        int from = 0;
        while (true) {
            int nk = inner.indexOf("\"name\"", from);
            if (nk < 0) break;
            int ncolon = inner.indexOf(':', nk);
            if (ncolon < 0) break;
            int q = skipWhitespace(inner, ncolon + 1);
            if (q < inner.length() && inner.charAt(q) == '"') {
                String name = extractQuoted(inner, q);
                name = stripColorCodes(unescape(name)).trim();
                if (!name.isEmpty()) names.add(name);
                from = q + 1;
            } else {
                from = ncolon + 1;
            }
        }
        return names;
    }

    /** Returns index of the bracket closing the array opened at openBracketIdx, or -1. */
    private static int findMatchingBracket(String s, int openBracketIdx) {
        int depth = 0;
        boolean inStr = false;
        for (int i = openBracketIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') {
                    i++;
                    continue;
                }
                if (c == '"') inStr = false;
            } else {
                if (c == '"') {
                    inStr = true;
                } else if (c == '[') {
                    depth++;
                } else if (c == ']') {
                    depth--;
                    if (depth == 0) return i;
                }
            }
        }
        return -1;
    }

    /** Extracts a string value of a nested key: {"version":{"name":"1.20.4"}}. */
    private static String extractObjectString(String json, String sectionKey, String valueKey) {
        int sec = json.indexOf("\"" + sectionKey + "\"");
        if (sec < 0) return null;
        int colon = json.indexOf(':', sec);
        if (colon < 0) return null;
        int brace = skipWhitespace(json, colon + 1);
        if (brace >= json.length() || json.charAt(brace) != '{') return null;
        int close = findMatchingBrace(json, brace);
        if (close < 0) return null;
        String inner = json.substring(brace, close + 1);
        int vk = inner.indexOf("\"" + valueKey + "\"");
        if (vk < 0) return null;
        int vcolon = inner.indexOf(':', vk);
        if (vcolon < 0) return null;
        int q = skipWhitespace(inner, vcolon + 1);
        if (q >= inner.length() || inner.charAt(q) != '"') return null;
        return extractQuoted(inner, q);
    }

    /** Extracts the MOTD from the "description" field, concatenating text parts. */
    private static String extractDescription(String json) {
        int desc = json.indexOf("\"description\"");
        if (desc < 0) return null;
        int colon = json.indexOf(':', desc);
        if (colon < 0) return null;
        int i = skipWhitespace(json, colon + 1);
        if (i >= json.length()) return null;
        if (json.charAt(i) == '"') {
            return extractQuoted(json, i);
        }
        if (json.charAt(i) != '{') return null;
        int close = findMatchingBrace(json, i);
        if (close < 0) return null;
        String inner = json.substring(i, close + 1);
        StringBuilder motd = new StringBuilder();
        int from = 0;
        while (true) {
            int tk = inner.indexOf("\"text\"", from);
            if (tk < 0) break;
            int tcolon = inner.indexOf(':', tk);
            if (tcolon < 0) break;
            int q = skipWhitespace(inner, tcolon + 1);
            String part = (q < inner.length() && inner.charAt(q) == '"') ? extractQuoted(inner, q) : null;
            if (part != null) motd.append(part);
            from = q < inner.length() ? q + 1 : inner.length();
        }
        return motd.toString();
    }

    /** Reads a quoted string starting at quoteIdx; keeps escape sequences for later unescape. */
    private static String extractQuoted(String s, int quoteIdx) {
        StringBuilder sb = new StringBuilder();
        int j = quoteIdx + 1;
        while (j < s.length()) {
            char c = s.charAt(j);
            if (c == '\\' && j + 1 < s.length()) {
                sb.append(c).append(s.charAt(j + 1));
                j += 2;
                continue;
            }
            if (c == '"') break;
            sb.append(c);
            j++;
        }
        return sb.toString();
    }

    private static int extractInt(String json, String key) {
        int idx = json.indexOf("\"" + key + "\"");
        if (idx < 0) return 0;
        int colon = json.indexOf(':', idx);
        if (colon < 0) return 0;
        int j = skipWhitespace(json, colon + 1);
        StringBuilder num = new StringBuilder();
        while (j < json.length() && (Character.isDigit(json.charAt(j)) || json.charAt(j) == '-')) {
            num.append(json.charAt(j));
            j++;
        }
        try {
            return Integer.parseInt(num.toString());
        } catch (NumberFormatException e) {
            return 0;
        }
    }

    private static int skipWhitespace(String s, int from) {
        int i = from;
        while (i < s.length() && Character.isWhitespace(s.charAt(i))) i++;
        return i;
    }

    /** Returns index of the brace closing the object opened at openBraceIdx, or -1. */
    private static int findMatchingBrace(String s, int openBraceIdx) {
        int depth = 0;
        boolean inStr = false;
        for (int i = openBraceIdx; i < s.length(); i++) {
            char c = s.charAt(i);
            if (inStr) {
                if (c == '\\') {
                    i++;
                    continue;
                }
                if (c == '"') inStr = false;
            } else {
                if (c == '"') {
                    inStr = true;
                } else if (c == '{') {
                    depth++;
                } else if (c == '}') {
                    depth--;
                    if (depth == 0) return i;
                }
            }
        }
        return -1;
    }

    /** Removes Minecraft section color codes (§X). */
    public static String stripColorCodes(String s) {
        if (s.indexOf('\u00A7') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\u00A7' && i + 1 < s.length()) {
                i++; // skip color code char
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /**
     * Decodes common JSON escapes including unicode escapes (color codes etc).
     * Package-private so tests can verify it.
     */
    static String unescape(String s) {
        if (s.indexOf('\\') < 0) return s;
        StringBuilder sb = new StringBuilder(s.length());
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            if (c == '\\' && i + 1 < s.length()) {
                char n = s.charAt(i + 1);
                switch (n) {
                    case 'n': sb.append('\n'); i++; break;
                    case 't': sb.append('\t'); i++; break;
                    case 'r': sb.append('\r'); i++; break;
                    case '"': sb.append('"'); i++; break;
                    case '\\': sb.append('\\'); i++; break;
                    case '/': sb.append('/'); i++; break;
                    case 'u': {
                        if (i + 5 < s.length()) {
                            try {
                                sb.append((char) Integer.parseInt(s.substring(i + 2, i + 6), 16));
                                i += 5;
                            } catch (NumberFormatException e) {
                                sb.append(c);
                            }
                        } else {
                            sb.append(c);
                        }
                        break;
                    }
                    default: sb.append(c); break;
                }
            } else {
                sb.append(c);
            }
        }
        return sb.toString();
    }

    /** Number of bytes a varint occupies on the wire. */
    private static int varIntLen(int value) {
        int len = 1;
        while ((value & ~0x7F) != 0) {
            value >>>= 7;
            len++;
        }
        return len;
    }

    private static void writeVarInt(DataOutputStream out, int value) throws IOException {
        while (true) {
            if ((value & ~0x7F) == 0) {
                out.writeByte(value);
                return;
            }
            out.writeByte((value & 0x7F) | 0x80);
            value >>>= 7;
        }
    }

    private static int readVarInt(DataInputStream in) throws IOException {
        int result = 0;
        int shift = 0;
        while (true) {
            byte b = in.readByte();
            result |= (b & 0x7F) << shift;
            if ((b & 0x80) == 0) break;
            shift += 7;
            if (shift > 35) throw new IOException("VarInt слишком большой");
        }
        return result;
    }
}