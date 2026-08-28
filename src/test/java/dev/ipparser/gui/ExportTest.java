package dev.ipparser.gui;

import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.ipparser.probe.McProbe;
import java.util.Arrays;
import java.util.Collections;
import java.util.Map;
import org.junit.jupiter.api.Test;

class ExportTest {

    @Test
    void telnetExportContainsHeaderAndResults() {
        Export.ExportParams p = new Export.ExportParams();
        p.mcMode = false;
        p.syntaxType = "regex";
        p.syntaxMode = "single";
        p.useCidr = true;
        p.patternDesc = "^95\\.31\\.\\d{1,3}\\.\\d$";
        p.portSpec = "2000";
        p.external = false;
        p.externalCount = 0;
        p.openResults = Arrays.asList("95.31.158.9:2000");
        p.mcResults = Collections.emptyMap();
        String out = Export.build(p);
        assertTrue(out.contains("Open ports: 1"));
        assertTrue(out.contains("95.31.158.9:2000"));
        assertTrue(out.contains("Telnet (TCP)"));
    }

    @Test
    void mcExportIncludesVersionBrand() {
        Export.ExportParams p = new Export.ExportParams();
        p.mcMode = true;
        p.syntaxType = "regex";
        p.syntaxMode = "single";
        p.useCidr = true;
        p.patternDesc = "x";
        p.portSpec = "25565";
        p.external = false;
        p.openResults = Arrays.asList("1.2.3.4:25565");
        McProbe.Result r = new McProbe.Result();
        r.version = "1.21.1";
        r.brand = "Paper";
        p.mcResults = Map.of("1.2.3.4:25565", r);
        String out = Export.build(p);
        assertTrue(out.contains("Minecraft (mcprobe)"));
        assertTrue(out.contains("version: 1.21.1"));
        assertTrue(out.contains("brand: Paper"));
    }

    @Test
    void emptyResultsExport() {
        Export.ExportParams p = new Export.ExportParams();
        p.mcMode = false;
        p.syntaxMode = "single";
        p.openResults = Collections.emptyList();
        p.mcResults = Collections.emptyMap();
        p.portSpec = "80";
        assertTrue(Export.build(p).contains("Open ports: 0"));
    }
}