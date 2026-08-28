package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.Color;
import java.awt.Font;
import java.awt.FontMetrics;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.LinearGradientPaint;
import java.awt.RenderingHints;
import java.util.Locale;
import javax.swing.JComponent;

/** Custom scan progress bar: yellow fill, thin white edge line, 5% ticks. */
public class ScanProgressBar extends JComponent {
    private double pct;

    public ScanProgressBar() {
        setOpaque(false);
    }

    public void setProgress(double pct) {
        this.pct = Math.max(0, Math.min(100, pct));
        repaint();
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        int w = getWidth();
        int left = 8;
        int right = Math.max(left + 1, w - 8);
        int barY = 14;
        int barH = 16;
        int barW = right - left;

        g2.setColor(Theme.BG_FIELD);
        g2.fillRoundRect(left, barY, barW, barH, barH, barH);
        g2.setColor(Theme.BORDER);
        g2.drawRoundRect(left, barY, barW, barH, barH, barH);

        int fillW = (int) Math.round(barW * pct / 100.0);
        if (fillW > 0) {
            g2.setPaint(new LinearGradientPaint(left, barY, left, barY + barH,
                    new float[]{0f, 1f},
                    new Color[]{new Color(255, 215, 90), new Color(240, 180, 50)}));
            g2.fillRoundRect(left, barY, Math.min(fillW, barW), barH, barH, barH);
            g2.setPaint(null);
        }

        int mx = Math.max(left + 1, Math.min(right - 1, left + fillW));
        g2.setColor(Color.WHITE);
        g2.fillRect(mx - 1, barY + 1, 2, barH - 2);

        String pctStr = String.format(Locale.US, "%.3f%%", pct);
        g2.setFont(new Font("Segoe UI", Font.BOLD, 11));
        FontMetrics fm = g2.getFontMetrics();
        int tw = fm.stringWidth(pctStr);
        int tx = left + (barW - tw) / 2;
        int ty = barY + barH / 2 + fm.getAscent() / 2 - 1;
        boolean textOverFill = tx + tw / 2 <= left + fillW;
        g2.setColor(textOverFill ? new Color(20, 21, 30) : Theme.TEXT_MAIN);
        g2.drawString(pctStr, tx, ty);

        g2.setFont(new Font("Segoe UI", Font.PLAIN, 9));
        FontMetrics fmT = g2.getFontMetrics();
        for (int t = 0; t <= 100; t += 5) {
            int tx2 = left + (int) (barW * t / 100.0);
            boolean major = t % 25 == 0;
            g2.setColor(major ? Theme.BORDER : Theme.BORDER.darker());
            g2.fillRect(tx2 - 1, barY + barH + 3, 2, major ? 5 : 3);
            if (major) {
                String lbl = t + "%";
                int lw = fmT.stringWidth(lbl);
                g2.setColor(Theme.TEXT_MUTED);
                g2.drawString(lbl, Math.max(left, Math.min(right - lw, tx2 - lw / 2)), barY + barH + 16);
            }
        }
        g2.dispose();
    }
}