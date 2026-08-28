package dev.ipparser.gui;

import dev.ipparser.gui.components.DarkCheckIcon;
import dev.ipparser.gui.components.RoundedButton;
import dev.ipparser.gui.components.RoundedPanel;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Cursor;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import javax.swing.Box;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;
import javax.swing.JTextField;

/**
 * Modal dialog with log output settings and MC-probe log filters.
 * Opened via the gear button next to the log window.
 */
public class LogSettingsDialog extends JDialog {

    private final IpParserFrame owner;
    private final LogConfig config;

    private final JCheckBox openCb, closedCb, timeoutCb, errorCb, actionsCb, status2Cb;
    private final JCheckBox fOnline, fVersion, fBrand, fMotd, fPlayers;
    private final JComboBox<String> opOnline, opVersion;
    private final JTextField valOnline, valVersion, valBrand, valMotd, valPlayers;

    public LogSettingsDialog(IpParserFrame owner) {
        super(owner, "Log Settings", true);
        this.owner = owner;
        this.config = owner.getLogConfig();
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel root = new JPanel(new BorderLayout(12, 12));
        root.setBackground(Theme.BG_ROOT);
        root.setBorder(javax.swing.BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel cols = new JPanel(new GridLayout(1, 2, 18, 0));
        cols.setOpaque(false);

        // ---- Left: Logs settings ----
        JPanel left = new RoundedPanel(12, Theme.BG_PANEL);
        left.setLayout(new GridBagLayout());
        left.setBorder(javax.swing.BorderFactory.createEmptyBorder(12, 14, 12, 14));
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(4, 4, 4, 4);
        g.anchor = GridBagConstraints.WEST;
        g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
        left.add(sectionTitle("Logs settings"), g);
        g.gridwidth = 1;
        g.gridy++;
        openCb = logCheckbox("Log available IP/Port connections", config.logOpen);
        left.add(openCb, g); g.gridy++;
        closedCb = logCheckbox("Log closed IP/Port connections", config.logClosed);
        left.add(closedCb, g); g.gridy++;
        timeoutCb = logCheckbox("Log timed out IP/Port connections", config.logTimeout);
        left.add(timeoutCb, g); g.gridy++;
        errorCb = logCheckbox("Log errored IP/Port connections", config.logError);
        left.add(errorCb, g); g.gridy++;
        actionsCb = logCheckbox("Log actions (e.g. change IP regex)", config.logActions);
        left.add(actionsCb, g); g.gridy++;
        status2Cb = logCheckbox("Status 2: port reachable from outside (public IP)", config.external);
        status2Cb.setToolTipText("Show port reachability from outside as a second status.\n"
                + "Public IP + open port = reachable from outside (port forwarded).\n"
                + "Works locally, no external services.");
        left.add(status2Cb, g);
        cols.add(left);

        // ---- Right: MC-probe log filter ----
        JPanel right = new RoundedPanel(12, Theme.BG_PANEL);
        right.setLayout(new GridBagLayout());
        right.setBorder(javax.swing.BorderFactory.createEmptyBorder(12, 14, 12, 14));
        GridBagConstraints gr = new GridBagConstraints();
        gr.insets = new Insets(4, 4, 4, 4);
        gr.anchor = GridBagConstraints.WEST;
        gr.gridx = 0; gr.gridy = 0; gr.gridwidth = 4;
        right.add(sectionTitle("MC-probe log filter"), gr);
        gr.gridwidth = 1;

        gr.gridy++;
        fOnline = logCheckbox("Log if online", config.mc.online);
        opOnline = opCombo(config.mc.onlineOp);
        valOnline = filterField(config.mc.onlineVal, "value / range, e.g. 5  or  10-30\n(above/below/in-range/out-of-range)");
        addFilterRow(right, gr, fOnline, opOnline, valOnline);

        gr.gridy++;
        fVersion = logCheckbox("Log if version", config.mc.version);
        opVersion = opCombo(config.mc.versionOp);
        valVersion = filterField(config.mc.versionVal, "value / range, e.g. 1.21.1  or  1.21.1-1.21.4\n(above/below/in-range/out-of-range)");
        addFilterRow(right, gr, fVersion, opVersion, valVersion);

        gr.gridy++;
        fBrand = logCheckbox("Log if brand name contains", config.mc.brand);
        valBrand = filterField(config.mc.brandVal, "java regex, e.g. Leaf|Paper  ((?i) for case-insensitive)");
        addFilterRow(right, gr, fBrand, null, valBrand);

        gr.gridy++;
        fMotd = logCheckbox("Log if MOTD contains", config.mc.motd);
        valMotd = filterField(config.mc.motdVal, "java regex, e.g. \\bAnarchy\\b");
        addFilterRow(right, gr, fMotd, null, valMotd);

        gr.gridy++;
        fPlayers = logCheckbox("Log if player list contains", config.mc.players);
        valPlayers = filterField(config.mc.playersVal, "java regex, e.g. Notch");
        addFilterRow(right, gr, fPlayers, null, valPlayers);

        gr.gridy++;
        JLabel hint = new JLabel("Empty value = filter disabled.\n"
                + "Operators: is / above / below / in-range.");
        hint.setFont(Theme.FONT_SMALL);
        hint.setForeground(Theme.TEXT_MUTED);
        gr.gridwidth = 4;
        right.add(hint, gr);
        cols.add(right);

        root.add(cols, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttons.setOpaque(false);
        RoundedButton ok = new RoundedButton("Apply", Theme.ACCENT_DARK, Theme.ACCENT);
        ok.addActionListener(e -> {
            apply();
            dispose();
        });
        RoundedButton cancel = new RoundedButton("Cancel", new Color(58, 61, 82), new Color(78, 82, 110));
        cancel.setForeground(Theme.TEXT_MAIN);
        cancel.addActionListener(e -> dispose());
        buttons.add(ok);
        buttons.add(cancel);
        root.add(buttons, BorderLayout.SOUTH);

        setContentPane(root);
        pack();
        setResizable(false);
    }

    private JLabel sectionTitle(String text) {
        JLabel l = new JLabel(text);
        l.setFont(new java.awt.Font("Segoe UI", java.awt.Font.BOLD, 14));
        l.setForeground(Theme.ACCENT);
        return l;
    }

    private JCheckBox logCheckbox(String text, boolean selected) {
        JCheckBox cb = new JCheckBox(text);
        cb.setOpaque(false);
        cb.setForeground(Theme.TEXT_MAIN);
        cb.setFont(Theme.FONT_LABEL);
        cb.setSelected(selected);
        cb.setIcon(new DarkCheckIcon());
        cb.setFocusPainted(false);
        cb.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        return cb;
    }

    private JComboBox<String> opCombo(String op) {
        JComboBox<String> cb = new JComboBox<>(McFilters.OPERATORS);
        owner.styleCombo(cb);
        cb.setSelectedItem(op);
        cb.setFont(Theme.FONT_SMALL);
        return cb;
    }

    private JTextField filterField(String value, String tooltip) {
        JTextField f = owner.makeField(value, 14);
        f.setToolTipText(tooltip);
        return f;
    }

    private void addFilterRow(JPanel panel, GridBagConstraints gr,
                              JCheckBox cb, JComboBox<String> op, JTextField field) {
        panel.add(cb, gr);
        gr.gridx = 1;
        if (op != null) {
            panel.add(op, gr);
        }
        gr.gridx = 2;
        panel.add(field, gr);
        gr.gridx = 3;
        panel.add(Box.createHorizontalStrut(8), gr);
        gr.gridx = 0;
        Runnable sync = () -> {
            boolean on = cb.isSelected();
            if (op != null) op.setEnabled(on);
            field.setEnabled(on);
        };
        cb.addItemListener(e -> sync.run());
        sync.run();
    }

    private void apply() {
        config.logOpen = openCb.isSelected();
        config.logClosed = closedCb.isSelected();
        config.logTimeout = timeoutCb.isSelected();
        config.logError = errorCb.isSelected();
        config.logActions = actionsCb.isSelected();
        config.external = status2Cb.isSelected();

        config.mc.online = fOnline.isSelected() && !valOnline.getText().trim().isEmpty();
        config.mc.onlineOp = (String) opOnline.getSelectedItem();
        config.mc.onlineVal = valOnline.getText().trim();

        config.mc.version = fVersion.isSelected() && !valVersion.getText().trim().isEmpty();
        config.mc.versionOp = (String) opVersion.getSelectedItem();
        config.mc.versionVal = valVersion.getText().trim();

        config.mc.brand = fBrand.isSelected() && !valBrand.getText().trim().isEmpty();
        config.mc.brandVal = valBrand.getText().trim();

        config.mc.motd = fMotd.isSelected() && !valMotd.getText().trim().isEmpty();
        config.mc.motdVal = valMotd.getText().trim();

        config.mc.players = fPlayers.isSelected() && !valPlayers.getText().trim().isEmpty();
        config.mc.playersVal = valPlayers.getText().trim();

        owner.saveSettings();
    }
}