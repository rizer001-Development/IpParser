package dev.ipparser.gui;

import java.awt.Color;
import javax.swing.BorderFactory;
import javax.swing.SwingUtilities;
import javax.swing.UIManager;
import javax.swing.plaf.ColorUIResource;

/**
 * Application entry point: configures the dark look-and-feel and opens the
 * main window on the EDT.
 */
public final class Main {

    private Main() {
    }

    public static void main(String[] args) {
        configureLookAndFeel();
        SwingUtilities.invokeLater(IpParserFrame::new);
    }

    private static void configureLookAndFeel() {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            UIManager.put("ToolTip.background", Theme.BG_PANEL_2);
            UIManager.put("ToolTip.foreground", Theme.TEXT_MAIN);
            UIManager.put("ToolTip.border", BorderFactory.createLineBorder(Theme.BORDER));
            // ComboBox dark: white text on gray, never white-on-white
            UIManager.put("ComboBox.background", new ColorUIResource(Theme.BG_FIELD));
            UIManager.put("ComboBox.foreground", new ColorUIResource(Theme.TEXT_MAIN));
            UIManager.put("ComboBox.selectionBackground", new ColorUIResource(Theme.ACCENT_DARK));
            UIManager.put("ComboBox.selectionForeground", new ColorUIResource(Color.WHITE));
            UIManager.put("ComboBox.buttonBackground", new ColorUIResource(Theme.BG_FIELD));
            UIManager.put("ComboBox.buttonForeground", new ColorUIResource(Theme.TEXT_MAIN));
        } catch (Exception ignored) {
            // Non-fatal: fall back to the default look and feel.
        }
    }
}