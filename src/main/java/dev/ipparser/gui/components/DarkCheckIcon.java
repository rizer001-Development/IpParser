package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.BasicStroke;
import java.awt.Component;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import javax.swing.Icon;
import javax.swing.JCheckBox;

/** Dark custom checkbox icon. */
public class DarkCheckIcon implements Icon {
    private final int size = 16;

    @Override
    public void paintIcon(Component c, Graphics g, int x, int y) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        g2.setColor(Theme.BG_FIELD);
        g2.fillRoundRect(x, y, size, size, 4, 4);
        g2.setColor(Theme.BORDER);
        g2.drawRoundRect(x, y, size, size, 4, 4);
        if (c instanceof JCheckBox cb && cb.isSelected()) {
            g2.setColor(Theme.ACCENT);
            g2.setStroke(new BasicStroke(2.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
            g2.drawLine(x + 3, y + 8, x + 6, y + 11);
            g2.drawLine(x + 6, y + 11, x + 13, y + 4);
        }
        g2.dispose();
    }

    @Override
    public int getIconWidth() {
        return size;
    }

    @Override
    public int getIconHeight() {
        return size;
    }
}