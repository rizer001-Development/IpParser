package dev.ipparser.pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;

import org.junit.jupiter.api.Test;

class SyntaxConvTest {

    @Test
    void ipTypeLiteral() {
        assertEquals("95\\.31\\.158\\.9", SyntaxConv.toRegex("95.31.158.9", "ip", false));
    }

    @Test
    void ipTypeWithCidr() {
        assertEquals("95\\.31\\.158\\.9/24", SyntaxConv.toRegex("95.31.158.9/24", "ip", true));
    }

    @Test
    void wildcardAllStars() {
        // * in third and fourth -> \d{1,3}
        assertEquals("95\\.31\\.\\d{1,3}\\.\\d{1,3}", SyntaxConv.toRegex("95.31.*.*", "wildcard", false));
    }

    @Test
    void wildcardMixedDigitStar() {
        assertEquals("95\\.31\\.1\\d0\\.1", SyntaxConv.toRegex("95.31.1*0.1", "wildcard", false));
    }

    @Test
    void wildcardWithCidrZeroesWildcardOctets() {
        assertEquals("95\\.31\\.0\\.0/8", SyntaxConv.toRegex("95.31.*.*/8", "wildcard", true));
    }

    @Test
    void invalidIpRejected() {
        assertNull(SyntaxConv.toRegex("95.31.158", "ip", true));
        assertNull(SyntaxConv.toRegex("999.1.1.1", "ip", true));
    }

    @Test
    void regexPassthrough() {
        assertEquals("95\\.31\\.0\\.0/16", SyntaxConv.toRegex("95\\.31\\.0\\.0/16", "regex", true));
    }

    @Test
    void slashDisallowedWhenCidrOff() {
        assertNull(SyntaxConv.toRegex("95.31.158.9/24", "ip", false));
    }

    @Test
    void nullAndBlankRejected() {
        assertNull(SyntaxConv.toRegex(null, "ip", true));
        assertNull(SyntaxConv.toRegex("   ", "regex", true));
    }
}