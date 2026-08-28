package dev.ipparser.pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import org.junit.jupiter.api.Test;

class IpPatternTest {

    @Test
    void countSimpleDigits() {
        assertEquals(10, IpPattern.countIps("192.168.1.\\d"));
    }

    @Test
    void countCidr() {
        assertEquals(256, IpPattern.countIps("192.168.1.0/24"));
        assertEquals(65536, IpPattern.countIps("95.31.0.0/16"));
        assertEquals(16_777_216, IpPattern.countIps("10.0.0.0/8"));
        // whole IPv4
        assertEquals(4_294_967_296L, IpPattern.countIps("0.0.0.0/0"));
    }

    @Test
    void countRegexIp() {
        assertEquals(2560, IpPattern.countIps("^95\\.31\\.\\d{1,3}\\.\\d$"));
    }

    @Test
    void countAlternation() {
        assertEquals(256L + 65536L, IpPattern.countIps("192.168.1.0/24|95.31.0.0/16"));
    }

    @Test
    void cidrBaseNeedNotBeAligned() {
        // 192.168.1.5/24 -> same block as 192.168.1.0/24
        assertEquals(IpPattern.countIps("192.168.1.0/24"), IpPattern.countIps("192.168.1.5/24"));
    }

    @Test
    void expandMatches() {
        Set<String> got = new HashSet<>(IpPattern.expand("10.0.0.0/29"));
        // /29 => 8 addresses 10.0.0.0..10.0.0.7
        assertEquals(8, got.size());
        assertTrue(got.contains("10.0.0.0"));
        assertTrue(got.contains("10.0.0.7"));
        assertFalse(got.contains("10.0.0.8"));
    }

    @Test
    void invalidReturnsEmpty() {
        assertTrue(IpPattern.blocks("not-an-ip").isEmpty());
        assertTrue(IpPattern.blocks("").isEmpty());
        assertTrue(IpPattern.blocks(null).isEmpty());
    }

    @Test
    void multipleCidrBlocksCombined() {
        List<List<List<Integer>>> blocks = IpPattern.blocks("95.31.0.0/16|10.0.0.0/8");
        assertEquals(2, blocks.size());
    }

    @Test
    void wildcardMixedOctetCounts() {
        // regex form produced by SyntaxConv from a wildcard: "1\d0" (100..190, 10 values)
        // and "\d" (10) => 100
        assertEquals(100, IpPattern.countIps("172.16.1\\d0.\\d"));
    }

    @Test
    void cidrOffTreatsSlashAsInvalid() {
        assertEquals(0, IpPattern.countIps("192.168.1.0/24", false));
    }

    @Test
    void structureOkDistinguishesAnchors() {
        assertTrue(IpPattern.structureOk("192.168.1.\\d"));
        assertTrue(IpPattern.structureOk("^192\\.168\\.1\\.\\d$"));
        assertFalse(IpPattern.structureOk("192.168.1"));
        assertFalse(IpPattern.structureOk(""));
    }

    @Test
    void countDoesNotBuildList() {
        // massive range must not overflow/crash
        assertEquals(4_294_967_296L, IpPattern.countIps("0.0.0.0/0"));
    }

    @Test
    void blocksAllCombinesLines() {
        List<String> lines = Arrays.asList("10.0.0.0/24", "192.168.1.0/24", "", " ");
        assertEquals(2, IpPattern.blocksAll(lines).size());
        assertEquals(512L, IpPattern.countIpsAll(lines));
    }
}