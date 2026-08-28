package dev.ipparser.core;

import java.net.Inet4Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.net.SocketException;
import java.util.ArrayList;
import java.util.Enumeration;
import java.util.List;

/**
 * Helpers for "Status 2": determine whether an IP is public ("white"),
 * whether it belongs to the local LAN, and the human-readable external verdict.
 * Pure local logic - no external services required.
 */
public final class IpUtils {

    private IpUtils() {
    }

    /**
     * Returns true if the IP is public ("white") - potentially reachable from the Internet.
     * Private/reserved ranges return false: RFC1918, loopback, link-local, CGNAT 100.64/10,
     * TEST-NET ranges, multicast, reserved.
     */
    public static boolean isPublic(String ip) {
        InetAddress addr = parse(ip);
        if (addr == null) return false;
        if (addr.isAnyLocalAddress() || addr.isLoopbackAddress()
                || addr.isLinkLocalAddress() || addr.isSiteLocalAddress()
                || addr.isMulticastAddress()) {
            return false;
        }
        int[] o = octets(ip);
        if (o == null) return false;
        int a = o[0], b = o[1];

        // CGNAT 100.64.0.0/10
        if (a == 100 && b >= 64 && b <= 127) return false;
        // 0.0.0.0/8
        if (a == 0) return false;
        // 192.0.0.0/24, 192.0.2.0/24 (TEST-NET-1), 192.88.99.0/24 (6to4 relay)
        if (a == 192 && (b == 0 || b == 88)) return false;
        // 198.18.0.0/15 (benchmarking), 198.51.100.0/24 (TEST-NET-2)
        if (a == 198 && (b == 18 || b == 19 || b == 51)) return false;
        // 203.0.113.0/24 (TEST-NET-3)
        if (a == 203 && b == 0) return false;
        // multicast 224/4 and reserved 240/4, broadcast
        return a < 224;
    }

    /**
     * Returns true if the IP belongs to the same /24 LAN as this machine.
     */
    public static boolean isSameLan(String ip) {
        int[] o = octets(ip);
        if (o == null) return false;
        for (String local : localIpv4s()) {
            int[] lo = octets(local);
            if (lo != null && lo[0] == o[0] && lo[1] == o[1] && lo[2] == o[2]) {
                return true;
            }
        }
        return false;
    }

    /**
     * Human-readable "Status 2" verdict for an IP:port based on the local scan result.
     */
    public static String externalStatus(String ip, boolean open, boolean timeout) {
        if (isSameLan(ip)) {
            return "адрес локальной сети — извне недоступен";
        }
        if (!isPublic(ip)) {
            return "серый IP (приватный) — извне недоступен";
        }
        if (open) {
            return "белый IP — порт доступен извне (проброшен)";
        }
        if (timeout) {
            return "белый IP — таймаут, доступность извне не определена";
        }
        return "белый IP — порт закрыт, извне недоступен";
    }

    private static InetAddress parse(String ip) {
        try {
            return InetAddress.getByName(ip);
        } catch (Exception e) {
            return null;
        }
    }

    private static int[] octets(String ip) {
        String[] p = ip.split("\\.");
        if (p.length != 4) return null;
        int[] o = new int[4];
        try {
            for (int i = 0; i < 4; i++) {
                o[i] = Integer.parseInt(p[i]);
                if (o[i] < 0 || o[i] > 255) return null;
            }
        } catch (NumberFormatException e) {
            return null;
        }
        return o;
    }

    private static List<String> localIpv4s() {
        List<String> out = new ArrayList<>();
        try {
            Enumeration<NetworkInterface> ifaces = NetworkInterface.getNetworkInterfaces();
            while (ifaces.hasMoreElements()) {
                NetworkInterface ni = ifaces.nextElement();
                Enumeration<InetAddress> addrs = ni.getInetAddresses();
                while (addrs.hasMoreElements()) {
                    InetAddress a = addrs.nextElement();
                    if (a instanceof Inet4Address && !a.isLoopbackAddress()) {
                        out.add(a.getHostAddress());
                    }
                }
            }
        } catch (SocketException ignored) {
        }
        return out;
    }
}