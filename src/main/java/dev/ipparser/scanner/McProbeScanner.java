package dev.ipparser.scanner;

import dev.ipparser.probe.McProbe;

/**
 * Multithreaded Minecraft server scanner built on the shared
 * {@link AbstractScanner} pipeline. Runs the Server List Ping protocol on each
 * target via {@link McProbe}.
 */
public class McProbeScanner extends AbstractScanner<McProbe.Result> {

    public McProbeScanner() {
        super("mcparse");
    }

    @Override
    protected McProbe.Result probe(String ip, int port, int timeoutMs) {
        return McProbe.ping(ip, port, timeoutMs);
    }
}