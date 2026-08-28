package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.Graphics;
import java.awt.Graphics2D;
import java.awt.RenderingHints;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.geom.RoundRectangle2D;
import javax.swing.BorderFactory;
import javax.swing.JButton;

/** Dark, rounded, hoverable button. */
public class RoundedButton extends JButton {
    private final Color baseBg;
    private final Color pressBg;
    private Color hoverBg;

    public RoundedButton(String text, Color base, Color hover) {
        super(text);
        this.baseBg = base;
        this.hoverBg = hover != null ? hover : base.brighter();
        this.pressBg = base.darker();
        setForeground(Color.WHITE);
        setFont(Theme.FONT_BTN);
        setFocusPainted(false);
        setContentAreaFilled(false);
        setBorderPainted(false);
        setOpaque(false);
        setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        setBorder(BorderFactory.createEmptyBorder(9, 18, 9, 18));
        addMouseListener(new MouseAdapter() {
            @Override
            public void mouseEntered(MouseEvent e) {
                if (isEnabled()) setBackground(hoverBg);
            }

            @Override
            public void mouseExited(MouseEvent e) {
                if (isEnabled()) setBackground(baseBg);
            }

            @Override
            public void mousePressed(MouseEvent e) {
                if (isEnabled()) setBackground(pressBg);
            }

            @Override
            public void mouseReleased(MouseEvent e) {
                if (isEnabled()) {
                    setBackground(getMousePosition() != null ? hoverBg : baseBg);
                }
            }
        });
        setBackground(baseBg);
    }

    public void setHoverBg(Color c) {
        this.hoverBg = c;
    }

    @Override
    protected void paintComponent(Graphics g) {
        Graphics2D g2 = (Graphics2D) g.create();
        g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
        Color c = getBackground();
        if (!isEnabled()) {
            c = new Color(52, 54, 70);
        }
        g2.setColor(c);
        g2.fill(new RoundRectangle2D.Float(0, 0, getWidth(), getHeight(), 10, 10));
        if (isEnabled()) {
            g2.setColor(new Color(255, 255, 255, 28));
            g2.fill(new RoundRectangle2D.Float(1, 1, getWidth() - 2, getHeight() / 2 - 2, 9, 9));
        }
        g2.dispose();
        super.paintComponent(g);
    }

    @Override
    public void setEnabled(boolean enabled) {
        super.setEnabled(enabled);
        if (enabled) {
            setForeground(Color.WHITE);
        } else {
            setForeground(new Color(120, 123, 145));
        }
    }
}