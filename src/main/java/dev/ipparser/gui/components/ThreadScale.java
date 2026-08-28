package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Dimension;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** Compact colored scale for the thread count (1-1000), like the IP scale. */
public class ThreadScale extends JPanel {
    private final ThreadGauge gauge = new ThreadGauge();
    private final JLabel label = new JLabel();

    public ThreadScale() {
        setOpaque(false);
        setLayout(new BorderLayout(8, 0));
        gauge.setPreferredSize(new Dimension(110, 22));
        gauge.setMinimumSize(new Dimension(90, 22));
        add(gauge, BorderLayout.WEST);
        label.setFont(new java.awt.Font("Segoe UI", java.awt.Font.PLAIN, 11));
        label.setForeground(Theme.TEXT_MUTED);
        add(label, BorderLayout.CENTER);
        setValue(50);
    }

    public void setValue(int threads) {
        ThreadBand band = ThreadBand.forValue(threads);
        gauge.setValue(threads);
        Color c = Theme.gradientColor((threads - 1.0) / 1023.0);
        label.setText("<html><b style='color:rgb(" + c.getRed() + "," + c.getGreen()
                + "," + c.getBlue() + ");'>" + threads + " network threads</b>  " + band.desc + "</html>");
    }
}