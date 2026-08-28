package dev.ipparser.gui.components;

import dev.ipparser.gui.Theme;
import java.awt.Color;

/** Color/description bands for the IP-count scale. */
public enum Band {
    NORMAL(new Color(88, 230, 140), "Normal - quick scan"),
    NORMAL_UP(new Color(170, 230, 90), "Normal - a minute or two"),
    ELEVATED(new Color(250, 200, 90), "Elevated - may take several minutes"),
    HIGH(new Color(255, 160, 60), "High - may take tens of minutes"),
    VERY_HIGH(new Color(255, 105, 105), "Very high - may take hours"),
    EXTREME(new Color(210, 70, 60), "Extreme - may take many hours"),
    MASSIVE(new Color(160, 60, 170), "Massive - may take days");

    public final Color color;
    public final String desc;

    Band(Color color, String desc) {
        this.color = color;
        this.desc = desc;
    }

    public static Band forCount(long count) {
        if (count <= 10_000) return NORMAL;
        if (count <= 100_000) return NORMAL_UP;
        if (count <= 1_000_000) return ELEVATED;
        if (count <= 10_000_000) return HIGH;
        if (count <= 100_000_000) return VERY_HIGH;
        if (count <= 1_000_000_000) return EXTREME;
        return MASSIVE;
    }

    @SuppressWarnings("unused")
    private static Color gradient(double t) {
        return Theme.gradientColor(t);
    }
}