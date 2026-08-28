package dev.ipparser.gui;

import dev.ipparser.core.IpUtils;
import dev.ipparser.probe.McProbe;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.List;
import java.util.Map;

/**
 * Pure content builder for the results export file (no Swing dependencies),
 * so the wording and formatting can be unit tested.
 */
public final class Export {

    private Export() {
    }

    public static String build(ExportParams p) {
        StringBuilder sb = new StringBuilder();
        sb.append("IP Parser - scan results").append('\n');
        sb.append("Time: ").append(new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date())).append('\n');
        sb.append("Mode: ").append(p.mcMode ? "Minecraft (mcprobe)" : "Telnet (TCP)").append('\n');
        sb.append("Syntax (type=").append(p.syntaxType)
                .append(", input=").append(p.syntaxMode.toLowerCase())
                .append(", CIDR=").append(p.useCidr ? "on" : "off")
                .append("): ").append(p.patternDesc).append('\n');
        sb.append("Port: ").append(p.portSpec).append('\n');
        sb.append("Open ports: ").append(p.openResults.size()).append('\n');
        if (p.external) {
            sb.append("Reachable from outside (public IP): ").append(p.externalCount).append('\n');
        }
        sb.append("------------------------------------------").append('\n');
        for (String res : p.openResults) {
            String line = res;
            if (p.mcMode) {
                McProbe.Result probe = p.mcResults.get(res);
                if (probe != null) {
                    String version = probe.version.isEmpty() ? "?" : probe.version;
                    line = res + "  |  version: " + version
                            + (probe.brand.isEmpty() ? "" : "  |  brand: " + probe.brand)
                            + "  |  players: " + probe.online + "/" + probe.max
                            + (probe.motd.isEmpty() ? "" : "  |  " + probe.motd);
                }
            }
            if (p.external) {
                String ip = res.contains(":") ? res.substring(0, res.lastIndexOf(':')) : res;
                line = line + "  —  " + IpUtils.externalStatus(ip, true, false);
            }
            sb.append(line).append('\n');
        }
        return sb.toString();
    }

    /** All inputs needed to render an export. */
    public static final class ExportParams {
        public boolean mcMode;
        public String syntaxType;
        public String syntaxMode;
        public boolean useCidr;
        public String patternDesc;
        public String portSpec;
        public boolean external;
        public long externalCount;
        public List<String> openResults;
        public Map<String, McProbe.Result> mcResults;
    }
}