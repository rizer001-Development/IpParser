package dev.ipparser.gui;

import java.awt.Color;
import java.awt.Font;

/**
 * Central place for the dark-theme palette, fonts and a few UI helpers that
 * used to live scattered through the monolithic window class.
 */
public final class Theme {

    private Theme() {
    }

    // ================= DARK THEME PALETTE =================
    public static final Color BG_ROOT        = new Color(17, 18, 26);
    public static final Color BG_PANEL       = new Color(27, 28, 40);
    public static final Color BG_PANEL_2     = new Color(32, 34, 48);
    public static final Color BG_FIELD       = new Color(40, 42, 58);
    public static final Color BG_LOG         = new Color(14, 15, 22);
    public static final Color BORDER         = new Color(58, 61, 82);
    public static final Color BORDER_FOCUS   = new Color(124, 108, 255);
    public static final Color ACCENT         = new Color(124, 108, 255);
    public static final Color ACCENT_DARK    = new Color(94, 78, 215);
    public static final Color TEXT_MAIN      = new Color(226, 227, 240);
    public static final Color TEXT_MUTED     = new Color(140, 143, 165);
    public static final Color GREEN          = new Color(88, 230, 140);
    public static final Color GREEN_DARK     = new Color(38, 140, 76);
    public static final Color RED            = new Color(255, 105, 105);
    public static final Color RED_DARK       = new Color(178, 58, 58);
    public static final Color YELLOW         = new Color(250, 200, 90);
    public static final Color GRAY           = new Color(168, 171, 190);
    public static final Color BLUE           = new Color(94, 160, 255);

    // ================= FONTS =================
    public static final Font FONT_BODY    = new Font("Segoe UI", Font.PLAIN, 13);
    public static final Font FONT_MONO    = new Font("Consolas", Font.PLAIN, 13);
    public static final Font FONT_TITLE   = new Font("Segoe UI", Font.BOLD, 20);
    public static final Font FONT_BTN     = new Font("Segoe UI", Font.BOLD, 13);
    public static final Font FONT_LABEL   = new Font("Segoe UI", Font.PLAIN, 12);
    public static final Font FONT_SMALL   = new Font("Segoe UI", Font.PLAIN, 11);
    public static final Font FONT_TINY    = new Font("Segoe UI", Font.PLAIN, 10);

    /** Smooth scale gradient: white -> yellow -> orange -> red -> burgundy. */
    public static final int[][] GRADIENT = {
            {255, 255, 255}, {250, 220, 90}, {255, 160, 60}, {255, 90, 90}, {140, 20, 40}
    };

    public static Color gradientColor(double t) {
        double x = Math.max(0.0, Math.min(1.0, t)) * (GRADIENT.length - 1);
        int i = (int) x;
        if (i >= GRADIENT.length - 1) {
            int[] c = GRADIENT[GRADIENT.length - 1];
            return new Color(c[0], c[1], c[2]);
        }
        double f = x - i;
        int r = (int) (GRADIENT[i][0] + (GRADIENT[i + 1][0] - GRADIENT[i][0]) * f);
        int g = (int) (GRADIENT[i][1] + (GRADIENT[i + 1][1] - GRADIENT[i][1]) * f);
        int b = (int) (GRADIENT[i][2] + (GRADIENT[i + 1][2] - GRADIENT[i][2]) * f);
        return new Color(r, g, b);
    }

    /** Position 0..1 of an IP count on the log scale. */
    public static double ipPosition(long count) {
        double logC = Math.log10(Math.max(count, 1));
        return Math.min(1.0, Math.max(0.0, logC / 12.0));
    }
}