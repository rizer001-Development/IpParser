package dev.ipparser.scanner;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;

import org.junit.jupiter.api.Test;

class PortScannerParseTest {

    @Test
    void singlePort() {
        assertArrayEquals(new int[]{2000, 2000}, PortScanner.parsePorts("2000"));
    }

    @Test
    void range() {
        assertArrayEquals(new int[]{2000, 2010}, PortScanner.parsePorts("2000-2010"));
    }

    @Test
    void reversedRangeIsSorted() {
        assertArrayEquals(new int[]{2000, 2010}, PortScanner.parsePorts("2010-2000"));
    }

    @Test
    void outOfBoundsClamped() {
        assertArrayEquals(new int[]{1, 65535}, PortScanner.parsePorts("0-70000"));
    }

    @Test
    void whitespaceTolerated() {
        assertArrayEquals(new int[]{80, 443}, PortScanner.parsePorts(" 80 - 443 "));
    }

    @Test
    void garbageFallsBack() {
        assertArrayEquals(new int[]{1, 1}, PortScanner.parsePorts("abc"));
        assertArrayEquals(new int[]{1, 1}, PortScanner.parsePorts(""));
    }
}