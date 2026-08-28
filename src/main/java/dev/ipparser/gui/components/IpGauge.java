package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.Color;
import java.awt.Font;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.LinearGradientPaint;
import java.awt.RenderingHints;
import javax.swing.JComponent;

/** Horizontal log-scale gauge with colored bands, ticks and a white marker. */
public class IpGauge extends JComponent {
    private static final double[] BOUNDS = {0, 4, 5, 6, 7, 8, 9, 12}; // log10 of count limits
    private static final String[] TICKS = {"1", "10k", "1M", "100M", "1B"};
    private static final double[] TICK_LOG = {0, 4, 6, 8, 9};

    private long count;
    private boolean valid;

    public void setCount(long count, boolean valid) {
        this.count = count;
        this.valid = valid;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        int left = 8;
        int right = w - 8;
        int barY = h / 2 - 6;
        int barH = 8;
        double span = BOUNDS[BOUNDS.length - 1] - BOUNDS[0];

        if (!valid) {
            g2.setColor(Theme.BG_PANEL_2);
            g2.fillRoundRect(left, barY, Math.max(1, right - left), barH, barH, barH);
            g2.setColor(Theme.TEXT_MUTED);
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 9));
            g2.drawString("no scale", left + 4, barY + barH + 10);
            g2.dispose();
            return;
        }

        float[] fractions = {0f, 0.25f, 0.5f, 0.75f, 1f};
        Color[] stops = {
                new Color(255, 255, 255), new Color(250, 220, 90),
                new Color(255, 160, 60), new Color(255, 90, 90), new Color(140, 20, 40)
        };
        g2.setPaint(new LinearGradientPaint(left, 0, right, 0, fractions, stops));
        g2.fillRoundRect(left, barY, Math.max(1, right - left), barH, barH, barH);
        g2.setPaint(null);

        g2.setColor(Theme.TEXT_MUTED);
        g2.setFont(new Font("Segoe UI", Font.PLAIN, 9));
        for (int i = 0; i < TICKS.length; i++) {
            double pos = (TICK_LOG[i] - BOUNDS[0]) / span;
            int tx = left + (int) ((right - left) * pos);
            g2.drawString(TICKS[i], tx - 8, barY + barH + 10);
        }

        double logC = Math.log10(Math.max(count, 1));
        double pos = Math.min(1.0, Math.max(0.0, logC / BOUNDS[BOUNDS.length - 1]));
        int mx = left + (int) ((right - left) * pos);
        g2.setColor(Color.BLACK);
        g2.fillRect(mx - 1, barY - 3, 2, barH + 6);
        g2.dispose();
    }
}