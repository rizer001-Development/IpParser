package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.Color;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.LinearGradientPaint;
import java.awt.RenderingHints;
import javax.swing.JComponent;

/** Horizontal linear gauge for the network thread count 1-1024. */
public class ThreadGauge extends JComponent {
    private static final double[] BOUNDS = {1, 16, 64, 256, 1024};
    private int value = 50;

    public void setValue(int value) {
        this.value = value;
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int h = getHeight();
        int left = 6;
        int right = w - 6;
        int barY = h / 2 - 4;
        int barH = 8;
        double span = BOUNDS[BOUNDS.length - 1] - BOUNDS[0];

        float[] fractions = {0f, 0.25f, 0.5f, 0.75f, 1f};
        Color[] stops = {
                new Color(255, 255, 255), new Color(250, 220, 90),
                new Color(255, 160, 60), new Color(255, 90, 90), new Color(140, 20, 40)
        };
        g2.setPaint(new LinearGradientPaint(left, 0, right, 0, fractions, stops));
        g2.fillRoundRect(left, barY, Math.max(1, right - left), barH, barH, barH);
        g2.setPaint(null);

        double pos = Math.min(1.0, Math.max(0.0, (value - BOUNDS[0]) / span));
        int mx = left + (int) ((right - left) * pos);
        g2.setColor(Color.BLACK);
        g2.fillRect(mx - 1, barY - 3, 2, barH + 6);
        g2.dispose();
    }
}