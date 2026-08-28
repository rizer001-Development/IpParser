package dev.ipparser.probe;

import static org.junit.jupiter.api.Assertions.assertEquals;

import org.junit.jupiter.api.Test;

class McProbeTest {

    @Test
    void stripsSectionColorCodes() {
        assertEquals("Anarchy", McProbe.stripColorCodes("\u00A7aAnarchy"));
        assertEquals("AB", McProbe.stripColorCodes("A\u00A7xB")); // color code + char are both dropped
    }

    @Test
    void unescapeBasics() {
        assertEquals("line\nnext", McProbe.unescape("line\\nnext"));
        assertEquals("a\"b", McProbe.unescape("a\\\"b"));
        assertEquals("back\\slash", McProbe.unescape("back\\\\slash"));
    }

    @Test
    void unescapeUnicode() {
        // \u00a7 is the section sign that color codes use
        assertEquals("\u00A7a", McProbe.unescape("\\u00a7a"));
    }

    @Test
    void unescapeNoEscapesPassthrough() {
        assertEquals("plain text", McProbe.unescape("plain text"));
    }
}