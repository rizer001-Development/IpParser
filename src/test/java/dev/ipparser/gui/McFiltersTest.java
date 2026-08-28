package dev.ipparser.gui;

import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import dev.ipparser.probe.McProbe;
import java.util.Arrays;
import org.junit.jupiter.api.Test;

class McFiltersTest {

    @Test
    void numInRangeOperators() {
        assertArrayEquals(new int[]{5, 5}, McFilters.parseNumRange("5"));
        assertArrayEquals(new int[]{10, 30}, McFilters.parseNumRange("10-30"));
        assertArrayEquals(new int[]{10, 30}, McFilters.parseNumRange("30-10"));
        assertEquals(null, McFilters.parseNumRange("abc"));
        assertEquals(null, McFilters.parseNumRange("1-2-3"));
    }

    @Test
    void numInRangeIs() {
        assertTrue(McFilters.numInRange(5, "is", new int[]{5, 5}));
        assertFalse(McFilters.numInRange(6, "is", new int[]{5, 5}));
    }

    @Test
    void versionOrdering() {
        assertEquals(0, McFilters.compareVersions("1.21.1", "1.21.1"));
        assertTrue(McFilters.compareVersions("1.21.4", "1.21.1") > 0);
        assertTrue(McFilters.compareVersions("1.21.1-SNAPSHOT", "1.21.1") == 0);
        assertTrue(McFilters.compareVersions("1.20.4", "1.21.0") < 0);
    }

    @Test
    void versionInRange() {
        assertTrue(McFilters.versionMatches("1.21.2", "in-range", "1.21.1-1.21.4"));
        assertFalse(McFilters.versionMatches("1.20.4", "in-range", "1.21.1-1.21.4"));
        assertTrue(McFilters.versionMatches("1.20.4", "out-of-range", "1.21.1-1.21.4"));
    }

    @Test
    void regexFindHandlesInvalid() {
        // invalid regex must be treated as "disabled" (returns true)
        assertTrue(McFilters.regexFind("anything", "["));
        assertTrue(McFilters.regexFind("Notch", "Notch"));
        assertFalse(McFilters.regexFind("Steve", "Notch"));
    }

    @Test
    void passesWithAllFiltersOff() {
        McFilters.Settings s = new McFilters.Settings();
        McProbe.Result p = new McProbe.Result();
        p.success = true;
        p.online = 3;
        p.version = "1.21.1";
        assertTrue(McFilters.passes(p, s));
    }

    @Test
    void passesMatchingPlayerFilter() {
        McFilters.Settings s = new McFilters.Settings();
        s.players = true;
        s.playersVal = "Notch";
        McProbe.Result p = new McProbe.Result();
        p.players = Arrays.asList("Steve", "Notch");
        assertTrue(McFilters.passes(p, s));
        p.players = Arrays.asList("Steve", "Alex");
        assertFalse(McFilters.passes(p, s));
    }
}