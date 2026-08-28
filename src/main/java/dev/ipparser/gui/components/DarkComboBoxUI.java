package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import javax.swing.JButton;
import javax.swing.plaf.basic.BasicArrowButton;
import javax.swing.plaf.basic.BasicComboBoxUI;

/** Basic ComboBox UI with a dark arrow button (fixes white-on-white). */
public class DarkComboBoxUI extends BasicComboBoxUI {
    @Override
    protected JButton createArrowButton() {
        JButton b = new BasicArrowButton(BasicArrowButton.SOUTH,
                Theme.BG_FIELD, Theme.BORDER, Theme.TEXT_MAIN, Theme.ACCENT);
        b.setFocusable(false);
        return b;
    }
}