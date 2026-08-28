package dev.ipparser.gui.components;

import java.awt.Color;

/** Color/description bands for the network thread count. */
public enum ThreadBand {
    LIGHT(new Color(88, 230, 140), "Light"),
    NORMAL(new Color(170, 230, 90), "Normal"),
    HEAVY(new Color(250, 200, 90), "Heavy - many sockets"),
    VERY_HEAVY(new Color(255, 105, 105), "Very heavy - may exhaust sockets");

    public final Color color;
    public final String desc;

    ThreadBand(Color color, String desc) {
        this.color = color;
        this.desc = desc;
    }

    public static ThreadBand forValue(int threads) {
        if (threads <= 16) return LIGHT;
        if (threads <= 64) return NORMAL;
        if (threads <= 256) return HEAVY;
        return VERY_HEAVY;
    }
}