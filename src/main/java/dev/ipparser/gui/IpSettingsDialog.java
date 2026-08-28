package dev.ipparser.gui;

import dev.ipparser.gui.components.RoundedButton;
import java.awt.BorderLayout;
import java.awt.FlowLayout;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.Insets;
import javax.swing.JComboBox;
import javax.swing.JDialog;
import javax.swing.JLabel;
import javax.swing.JPanel;

/**
 * Modal dialog with the IP parsing settings: type (ip / wildcard / regex),
 * input mode (single / list / file) and the CIDR toggle.
 * Opened via the gear button next to the Syntax field.
 */
public class IpSettingsDialog extends JDialog {

    private final IpParserFrame owner;
    private final JComboBox<String> typeCombo, modeCombo, cidrCombo;
    private final JLabel hintLabel;

    public IpSettingsDialog(IpParserFrame owner) {
        super(owner, "IP parsing settings", true);
        this.owner = owner;
        setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

        JPanel root = new JPanel(new BorderLayout(12, 12));
        root.setBackground(Theme.BG_ROOT);
        root.setBorder(javax.swing.BorderFactory.createEmptyBorder(16, 16, 16, 16));

        JPanel form = new JPanel(new GridBagLayout());
        form.setOpaque(false);
        GridBagConstraints g = new GridBagConstraints();
        g.insets = new Insets(5, 4, 5, 4);
        g.anchor = GridBagConstraints.WEST;

        g.gridx = 0; g.gridy = 0;
        form.add(owner.makeLabel("Type"), g);
        g.gridx = 1; g.gridwidth = 2; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
        typeCombo = new JComboBox<>(new String[]{"ip", "wildcard", "regex"});
        owner.styleCombo(typeCombo);
        typeCombo.setSelectedItem(owner.getSyntaxType());
        typeCombo.setToolTipText("How the Syntax field is interpreted:"
                + "\nip - a full IP, e.g. 95.31.158.9"
                + "\nwildcard - * means any number, e.g. 95.31.***.*"
                + "\nregex - a Java regex, e.g. ^95\\.31\\.\\d{1,3}\\.\\d$");
        typeCombo.addActionListener(e -> updateHint());
        form.add(typeCombo, g);
        g.gridwidth = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE;

        g.gridy = 1; g.gridx = 0;
        form.add(owner.makeLabel("Input mode"), g);
        g.gridx = 1; g.gridwidth = 2; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
        modeCombo = new JComboBox<>(new String[]{"Single", "List", "File"});
        owner.styleCombo(modeCombo);
        modeCombo.setSelectedItem(owner.getSyntaxMode());
        modeCombo.setToolTipText("Single - one pattern\nList - several patterns, one per line\nFile - path to a file with one pattern per line");
        form.add(modeCombo, g);
        g.gridwidth = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE;

        g.gridy = 2; g.gridx = 0;
        form.add(owner.makeLabel("Use CIDR"), g);
        g.gridx = 1; g.gridwidth = 2; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
        cidrCombo = new JComboBox<>(new String[]{"no", "yes"});
        owner.styleCombo(cidrCombo);
        cidrCombo.setSelectedItem(owner.isUseCidr() ? "yes" : "no");
        cidrCombo.setToolTipText("Interpret CIDR blocks: 95.31.0.0/16, 95.31.158.9/24, 95.31.***.*/8");
        cidrCombo.addActionListener(e -> updateHint());
        form.add(cidrCombo, g);
        g.gridwidth = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE;

        g.gridy = 3; g.gridx = 0; g.gridwidth = 3; g.insets = new Insets(10, 4, 0, 4);
        hintLabel = new JLabel();
        hintLabel.setFont(Theme.FONT_SMALL);
        hintLabel.setForeground(Theme.TEXT_MUTED);
        form.add(hintLabel, g);
        updateHint();

        root.add(form, BorderLayout.CENTER);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
        buttons.setOpaque(false);
        RoundedButton apply = new RoundedButton("Apply", Theme.ACCENT_DARK, Theme.ACCENT);
        apply.addActionListener(e -> {
            owner.setSyntaxType((String) typeCombo.getSelectedItem());
            owner.setSyntaxMode((String) modeCombo.getSelectedItem());
            owner.setUseCidr("yes".equals(cidrCombo.getSelectedItem()));
            owner.applySyntaxMode();
            owner.saveSettings();
            dispose();
        });
        RoundedButton cancel = new RoundedButton("Cancel", new java.awt.Color(58, 61, 82), new java.awt.Color(78, 82, 110));
        cancel.setForeground(Theme.TEXT_MAIN);
        cancel.addActionListener(e -> dispose());
        buttons.add(apply);
        buttons.add(cancel);
        root.add(buttons, BorderLayout.SOUTH);

        setContentPane(root);
        pack();
        setResizable(false);
    }

    private void updateHint() {
        String type = (String) typeCombo.getSelectedItem();
        String cidr = "yes".equals(cidrCombo.getSelectedItem())
                ? "  |  CIDR: 95.31.158.9/24 or 95.31.***.*/8" : "";
        switch (type) {
            case "ip":
                hintLabel.setText("Full IP, e.g. 95.31.158.9" + cidr);
                break;
            case "wildcard":
                hintLabel.setText("* = any number, e.g. 95.31.***.*" + cidr);
                break;
            default:
                hintLabel.setText("Java regex, e.g. ^95\\.31\\.\\d{1,3}\\.\\d$" + cidr);
        }
    }
}