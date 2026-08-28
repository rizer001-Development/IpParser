package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.BorderLayout;
import java.awt.Color;
import javax.swing.BoxLayout;
import javax.swing.JLabel;
import javax.swing.JPanel;

/** Live IP-count scale: colored gauge + count + description, next to the Syntax field. */
public class IpScale extends JPanel {
    private final IpGauge gauge = new IpGauge();
    private final JLabel countLabel = new JLabel();
    private final JLabel descLabel = new JLabel();

    public IpScale() {
        setOpaque(false);
        setLayout(new BorderLayout(10, 0));

        gauge.setPreferredSize(new java.awt.Dimension(150, 36));
        gauge.setMinimumSize(new java.awt.Dimension(120, 36));
        add(gauge, BorderLayout.WEST);

        JPanel text = new JPanel();
        text.setOpaque(false);
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        countLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 12));
        descLabel.setFont(new java.awt.Font("Segoe UI", java.awt.Font.PLAIN, 11));
        descLabel.setForeground(Theme.TEXT_MUTED);
        text.add(countLabel);
        text.add(descLabel);
        add(text, BorderLayout.CENTER);

        setState(false, 0);
    }

    public void setState(boolean structureOk, long count) {
        boolean valid = structureOk && count > 0;
        gauge.setCount(count, valid);
        if (!structureOk) {
            countLabel.setForeground(Theme.RED);
            countLabel.setText("Invalid regex");
            descLabel.setText("4 octets 0-255, dots between");
        } else if (!valid) {
            countLabel.setForeground(Theme.GRAY);
            countLabel.setText("No IPs matched");
            descLabel.setText("Nothing matches in the 0-255 range");
        } else {
            Band band = Band.forCount(count);
            countLabel.setForeground(Theme.gradientColor(Theme.ipPosition(count)));
            countLabel.setText(formatCount(count));
            descLabel.setText(band.desc);
        }
    }

    private String formatCount(long n) {
        if (n >= 1_000_000_000L) {
            return String.format(java.util.Locale.US, "%.1f B IPs", n / 1_000_000_000.0);
        }
        if (n >= 1_000_000L) {
            return String.format(java.util.Locale.US, "%.1f M IPs", n / 1_000_000.0);
        }
        return String.format(java.util.Locale.US, "%,d IPs", n);
    }
}