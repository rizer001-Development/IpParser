package dev.ipparser.gui;

import static dev.ipparser.gui.Theme.ACCENT;
import static dev.ipparser.gui.Theme.ACCENT_DARK;
import static dev.ipparser.gui.Theme.BG_FIELD;
import static dev.ipparser.gui.Theme.BG_PANEL;
import static dev.ipparser.gui.Theme.BG_PANEL_2;
import static dev.ipparser.gui.Theme.BLUE;
import static dev.ipparser.gui.Theme.BORDER;
import static dev.ipparser.gui.Theme.FONT_BODY;
import static dev.ipparser.gui.Theme.FONT_LABEL;
import static dev.ipparser.gui.Theme.FONT_MONO;
import static dev.ipparser.gui.Theme.GRAY;
import static dev.ipparser.gui.Theme.GREEN;
import static dev.ipparser.gui.Theme.GREEN_DARK;
import static dev.ipparser.gui.Theme.RED;
import static dev.ipparser.gui.Theme.RED_DARK;
import static dev.ipparser.gui.Theme.TEXT_MAIN;
import static dev.ipparser.gui.Theme.TEXT_MUTED;
import static dev.ipparser.gui.Theme.YELLOW;

import dev.ipparser.core.AppPaths;
import dev.ipparser.core.IpUtils;
import dev.ipparser.core.PerfMonitor;
import dev.ipparser.gui.components.DarkComboBoxUI;
import dev.ipparser.gui.components.IpScale;
import dev.ipparser.gui.components.RoundedButton;
import dev.ipparser.gui.components.RoundedPanel;
import dev.ipparser.gui.components.ScanProgressBar;
import dev.ipparser.gui.components.ThreadScale;
import dev.ipparser.pattern.IpPattern;
import dev.ipparser.pattern.SyntaxConv;
import dev.ipparser.probe.McProbe;
import dev.ipparser.scanner.AbstractScanner;
import dev.ipparser.scanner.McProbeScanner;
import dev.ipparser.scanner.PortScanner;
import dev.ipparser.storage.AppDb;
import dev.ipparser.storage.FileLog;
import java.awt.BorderLayout;
import java.awt.Color;
import java.awt.Component;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.Font;
import java.awt.GridBagConstraints;
import java.awt.GridBagLayout;
import java.awt.GridLayout;
import java.awt.Insets;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicLong;
import javax.swing.BorderFactory;
import javax.swing.DefaultListCellRenderer;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JComponent;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JList;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JSpinner;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.JTextPane;
import javax.swing.SpinnerNumberModel;
import javax.swing.SwingUtilities;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.BadLocationException;
import javax.swing.text.Style;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;

/**
 * Main application window: layout, scan orchestration and results logging.
 * Replaces the former monolithic {@code IpParserGUI}. Helper concerns that used
 * to live inline here have been extracted into separate classes:
 *   - {@link McFilters}   - pure MC-probe log-filter logic
 *   - {@link Export}      - pure export-content builder
 *   - {@link LogSettingsDialog} / {@link IpSettingsDialog} - the two gear dialogs
 *   - {@link Theme} / {@code gui.components.*}              - UI building blocks
 *   - {@link AppDb}       - SQLite settings store (replaces settings.txt)
 *   - {@link FileLog}     - per-scan log files
 *
 * Counters are {@link AtomicLong} (the old code used plain volatile int,
 * losing updates because several parser threads incremented them at once).
 */
public class IpParserFrame extends JFrame {

    // ================= COMPONENTS =================
    private JTextField ipPatternField;
    private JTextField fileField;
    private JScrollPane fileFieldScroll;
    private RoundedButton syntaxSettingsButton;
    private JButton browseButton;
    private JTextArea listArea;
    private JScrollPane listScroll;
    private JTextField portField;

    // ---- IP parsing settings (Syntax gear button) ----
    private String syntaxType = "regex";    // ip / wildcard / regex
    private String syntaxMode = "Single";   // Single / List / File
    private boolean useCidr = true;         // CIDR interpretation on/off
    private JTextField timeoutField;
    private JSpinner parseSpinner;
    private JSpinner genSpinner;
    private JSpinner netSpinner;
    private JTextPane logPane;
    private StyledDocument logDoc;
    private JLabel statusLabel;
    private JLabel totalLabel;
    private JLabel openLabel;
    private JLabel closedLabel;
    private ScanProgressBar progressBar;
    private RoundedButton startButton;
    private RoundedButton stopButton;
    private RoundedButton exportButton;
    private RoundedButton clearButton;
    private JCheckBox externalCheck; // Status 2 toggle - controlled from Log Settings dialog
    private JLabel externalLabel;
    private JComboBox<String> modeCombo;
    private IpScale scalePanel;
    private ThreadScale threadScale;
    private JLabel cpuLabel;
    private JLabel ramLabel;
    private JLabel inLabel;
    private JLabel outLabel;

    private final LogConfig logConfig = LogConfig.load();
    private final McFilters.Settings mcFilters = logConfig.mc;

    private AbstractScanner<?> scanner;
    private final List<String> openResults = new CopyOnWriteArrayList<>();
    private final Map<String, McProbe.Result> mcResults = new ConcurrentHashMap<>();

    private static final SimpleDateFormat TIME_FMT = new SimpleDateFormat("HH:mm:ss");

    private volatile long totalTargets = 0;
    private final AtomicLong openCount = new AtomicLong(0);
    private final AtomicLong closedCount = new AtomicLong(0);
    private final AtomicLong externalCount = new AtomicLong(0);
    private volatile int scannedNow = 0;
    private volatile long lastProgressPosted = 0;
    private volatile long scanStartNanos = 0;

    public IpParserFrame() {
        super("IP Parser - IP and port scanner");
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        java.net.URL iconUrl = IpParserFrame.class.getResource("/app-icon.png");
        if (iconUrl != null) setIconImage(new javax.swing.ImageIcon(iconUrl).getImage());
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (scanner != null) scanner.stop();
                FileLog.get().close();
                dispose();
                System.exit(0);
            }
        });

        buildUi();
        setSize(860, 700);
        setMinimumSize(new Dimension(700, 560));
        setLocationRelativeTo(null);
        setVisible(true);
        loadSettings();

        // real-time system monitor tick (CPU / RAM / traffic)
        new javax.swing.Timer(1000, e -> refreshPerf()).start();
        FileLog.get().info("UI ready");
    }

    private void buildUi() {
        JPanel root = new JPanel(new BorderLayout(0, 10));
        root.setBackground(Theme.BG_ROOT);
        root.setBorder(BorderFactory.createEmptyBorder(12, 12, 12, 12));

        // ---- Header ----
        JPanel header = new RoundedPanel(14, Theme.BG_PANEL);
        header.setLayout(new BorderLayout(10, 0));
        totalLabel = makeStat("Total: 0", TEXT_MUTED);
        openLabel = makeStat("Open: 0", GREEN);
        externalLabel = makeStat("External: 0", BLUE);
        closedLabel = makeStat("Closed: 0", RED);
        JPanel stats = new JPanel(new FlowLayout(FlowLayout.RIGHT, 16, 6));
        stats.setOpaque(false);
        stats.add(totalLabel);
        stats.add(openLabel);
        stats.add(externalLabel);
        stats.add(closedLabel);
        header.add(stats, BorderLayout.EAST);
        JLabel subtitle = new JLabel("Pattern-based IP scanner and port checker");
        subtitle.setFont(FONT_LABEL);
        subtitle.setForeground(TEXT_MUTED);
        header.add(subtitle, BorderLayout.WEST);
        root.add(header, BorderLayout.NORTH);

        // ---- Settings panel ----
        JPanel settings = new RoundedPanel(14, Theme.BG_PANEL);
        settings.setLayout(new GridBagLayout());
        settings.setBorder(BorderFactory.createEmptyBorder(14, 18, 14, 18));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 6, 5, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Syntax mode + input + live IP-count scale
        gbc.gridx = 0; gbc.gridy = 0;
        settings.add(makeLabel("Syntax"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0; gbc.insets = new Insets(5, 6, 5, 6);

        JPanel syntaxRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        syntaxRow.setOpaque(false);
        ipPatternField = makeField("95\\.31\\.\\d{1,3}\\.\\d");
        ipPatternField.setToolTipText("Java regex for IPv4 addresses; CIDR blocks work inside the regex.\n"
                + "Examples: ^95\\.31\\.\\d{1,3}\\.\\d$  |  95\\.31\\.0\\.0/16  |  10.0.0.0/8  |  95\\.31\\.0\\.0/16|10\\.0\\.0\\.0/8");
        syntaxRow.add(ipPatternField);

        listArea = new JTextArea(4, 26);
        listArea.setBackground(BG_FIELD);
        listArea.setForeground(TEXT_MAIN);
        listArea.setCaretColor(TEXT_MAIN);
        listArea.setFont(FONT_MONO);
        listArea.setLineWrap(false);
        listArea.setBorder(BorderFactory.createEmptyBorder(6, 10, 6, 10));
        listArea.setToolTipText("Several regexes / CIDR blocks, one per line.\nEach line is scanned; the scale sums the IPs of all lines.");
        listScroll = new JScrollPane(listArea);
        listScroll.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        listScroll.getViewport().setBackground(BG_FIELD);
        syntaxRow.add(listScroll);

        fileField = makeField("", 13);
        fileField.setToolTipText("Patterns file path - long paths scroll inside the field");
        fileField.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));
        fileFieldScroll = new JScrollPane(fileField);
        fileFieldScroll.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        fileFieldScroll.setHorizontalScrollBarPolicy(JScrollPane.HORIZONTAL_SCROLLBAR_AS_NEEDED);
        fileFieldScroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_NEVER);
        fileFieldScroll.getViewport().setBackground(BG_FIELD);
        fileField.addMouseMotionListener(new MouseAdapter() {
            @Override
            public void mouseMoved(MouseEvent e) {
                String t = fileField.getText().trim();
                fileField.setToolTipText(t.isEmpty()
                        ? "Choose a patterns file (folder icon) - long paths scroll inside the field"
                        : t);
            }
        });
        syntaxRow.add(fileFieldScroll);

        browseButton = new JButton("\uD83D\uDCC2");
        browseButton.setFont(new Font("Segoe UI", Font.PLAIN, 14));
        browseButton.setBackground(BG_FIELD);
        browseButton.setForeground(TEXT_MAIN);
        browseButton.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        browseButton.setFocusPainted(false);
        browseButton.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        browseButton.setToolTipText("Choose a patterns file");
        browseButton.addActionListener(e -> choosePatternFile());
        syntaxRow.add(browseButton);

        syntaxSettingsButton = new RoundedButton("\u2699", new Color(58, 61, 82), new Color(78, 82, 110));
        syntaxSettingsButton.setForeground(TEXT_MAIN);
        syntaxSettingsButton.setToolTipText("IP parsing settings: type (ip / wildcard / regex), input mode (single / list / file), CIDR");
        syntaxSettingsButton.addActionListener(e -> openIpSettings());
        syntaxRow.add(syntaxSettingsButton);

        settings.add(syntaxRow, gbc);
        gbc.weightx = 0;

        gbc.gridx = 2; gbc.gridy = 0; gbc.gridwidth = 2; gbc.weightx = 1.2; gbc.insets = new Insets(2, 16, 2, 6);
        scalePanel = new IpScale();
        settings.add(scalePanel, gbc);
        gbc.gridwidth = 1; gbc.weightx = 0;

        applySyntaxMode();

        // Row 1: Port / range + Timeout
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 4; gbc.weightx = 1.0;
        gbc.insets = new Insets(5, 6, 5, 6);
        JPanel portRow = new JPanel(new FlowLayout(FlowLayout.LEFT, 8, 0));
        portRow.setOpaque(false);
        portRow.add(makeLabel("Port / range"));
        portField = makeField("2000", 10);
        portField.setToolTipText("Single port: 2000  or  range: 2000-2010  (e.g. 65534-65535)");
        portRow.add(portField);
        portRow.add(makeLabel("Timeout (ms)"));
        timeoutField = makeField("1500", 6);
        timeoutField.setToolTipText("Response wait time per port (50-60000)");
        portRow.add(timeoutField);
        settings.add(portRow, gbc);
        gbc.gridwidth = 1; gbc.weightx = 0;

        // Row 2: CPU + network threads
        gbc.gridx = 0; gbc.gridy = 2; gbc.insets = new Insets(5, 6, 5, 6);
        settings.add(makeLabel("Threads"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.3;
        JPanel threadFields = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        threadFields.setOpaque(false);
        int cores = Runtime.getRuntime().availableProcessors();
        threadFields.add(makeLabel("Parse:"));
        parseSpinner = new JSpinner(new SpinnerNumberModel(cores, 1, cores, 1));
        styleSpinner(parseSpinner);
        parseSpinner.setToolTipText("CPU threads that process results (max " + cores + " = CPU cores)");
        threadFields.add(parseSpinner);
        threadFields.add(makeLabel("Gen:"));
        genSpinner = new JSpinner(new SpinnerNumberModel(Math.min(4, cores), 1, cores, 1));
        styleSpinner(genSpinner);
        genSpinner.setToolTipText("CPU threads that generate IPs (max " + cores + " = CPU cores)");
        threadFields.add(genSpinner);
        threadFields.add(makeLabel("Net:"));
        netSpinner = new JSpinner(new SpinnerNumberModel(100, 1, 1024, 1));
        styleSpinner(netSpinner);
        netSpinner.setToolTipText("Network threads (socket I/O) - independent of CPU threads, max 1024");
        threadFields.add(netSpinner);
        settings.add(threadFields, gbc);
        gbc.weightx = 0;

        gbc.gridx = 2; gbc.gridy = 2; gbc.gridwidth = 2; gbc.weightx = 1.2; gbc.insets = new Insets(2, 16, 2, 6);
        threadScale = new ThreadScale();
        settings.add(threadScale, gbc);
        gbc.gridwidth = 1; gbc.weightx = 0;

        // Row 3: Mode selector
        gbc.gridx = 0; gbc.gridy = 3; gbc.insets = new Insets(5, 6, 5, 6);
        settings.add(makeLabel("Mode"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3; gbc.weightx = 1.0;
        modeCombo = new JComboBox<>(new String[]{"Telnet (TCP port)", "Minecraft (mcprobe)"});
        styleCombo(modeCombo);
        settings.add(modeCombo, gbc);
        gbc.gridwidth = 1; gbc.weightx = 0;

        // Row 4: port format hint
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 4; gbc.insets = new Insets(8, 6, 2, 6);
        JLabel portHint = new JLabel("\uD83D\uDD11 Port format:  2000  (single)  or  2000-2010  (range)");
        portHint.setFont(FONT_LABEL);
        portHint.setForeground(TEXT_MUTED);
        settings.add(portHint, gbc);
        gbc.gridwidth = 1;

        // Status 2 toggle: not added to layout; controlled from the Log Settings dialog.
        externalCheck = new JCheckBox("Status 2");
        externalCheck.setOpaque(false);
        externalCheck.setSelected(false);
        externalCheck.setToolTipText("Status 2: show port reachability from outside (public IP / port forwarding).\n"
                + "Configured in Log Settings (gear button next to the log).");

        DocumentListener scaleListener = new DocumentListener() {
            @Override public void insertUpdate(DocumentEvent e) { updateScale(); }
            @Override public void removeUpdate(DocumentEvent e) { updateScale(); }
            @Override public void changedUpdate(DocumentEvent e) { updateScale(); }
        };
        ipPatternField.getDocument().addDocumentListener(scaleListener);
        fileField.getDocument().addDocumentListener(scaleListener);
        listArea.getDocument().addDocumentListener(scaleListener);
        updateScale();
        netSpinner.addChangeListener(e -> updateThreadScale());
        updateThreadScale();

        root.add(settings, BorderLayout.NORTH);

        // ---- Log (CENTER - main area) ----
        JPanel logPanel = new RoundedPanel(14, Theme.BG_PANEL);
        logPanel.setLayout(new BorderLayout(0, 8));
        logPanel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));

        JPanel logHeader = new JPanel(new BorderLayout());
        logHeader.setOpaque(false);
        JLabel logTitle = new JLabel("\uD83D\uDCCB  Log — scan results");
        logTitle.setFont(new Font("Segoe UI", Font.BOLD, 14));
        logTitle.setForeground(TEXT_MAIN);
        logHeader.add(logTitle, BorderLayout.WEST);
        RoundedButton logSettingsButton = new RoundedButton("\u2699  Settings", new Color(58, 61, 82), new Color(78, 82, 110));
        logSettingsButton.setHoverBg(new Color(78, 82, 110));
        logSettingsButton.setForeground(TEXT_MAIN);
        logSettingsButton.setToolTipText("Log settings and MC-probe log filters");
        logSettingsButton.addActionListener(e -> openLogSettings());
        logHeader.add(logSettingsButton, BorderLayout.EAST);
        logPanel.add(logHeader, BorderLayout.NORTH);

        logPane = new JTextPane();
        logDoc = logPane.getStyledDocument();
        logPane.setEditable(false);
        logPane.setBackground(Theme.BG_LOG);
        logPane.setFont(FONT_MONO);
        logPane.setCaretColor(TEXT_MUTED);
        logPane.setFocusable(true);
        logPane.setBorder(BorderFactory.createEmptyBorder(8, 10, 8, 10));

        JScrollPane scroll = new JScrollPane(logPane);
        scroll.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        scroll.getViewport().setBackground(Theme.BG_LOG);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        logPanel.add(scroll, BorderLayout.CENTER);
        root.add(logPanel, BorderLayout.CENTER);

        // ---- Bottom: buttons + status ----
        JPanel bottom = new JPanel(new BorderLayout(0, 8));
        bottom.setOpaque(false);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        buttons.setOpaque(false);

        startButton = new RoundedButton("\u25B6  Start", GREEN_DARK, GREEN);
        startButton.addActionListener(e -> startScan());
        stopButton = new RoundedButton("\u25A0  Stop", RED_DARK, RED);
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopScan());
        exportButton = new RoundedButton("\uD83D\uDCC4  Export", ACCENT_DARK, ACCENT);
        exportButton.setEnabled(false);
        exportButton.addActionListener(e -> exportResults());
        clearButton = new RoundedButton("Clear log", new Color(58, 61, 82), new Color(78, 82, 110));
        clearButton.setForeground(TEXT_MAIN);
        clearButton.addActionListener(e -> clearAll());
        buttons.add(startButton);
        buttons.add(stopButton);
        buttons.add(exportButton);
        buttons.add(clearButton);
        bottom.add(buttons, BorderLayout.NORTH);

        JPanel monitorPanel = new RoundedPanel(12, Theme.BG_PANEL_2);
        monitorPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 20, 6));
        monitorPanel.setBorder(BorderFactory.createEmptyBorder(6, 12, 6, 12));
        cpuLabel = makeMonitorStat("CPU", "--");
        ramLabel = makeMonitorStat("RAM", "--");
        inLabel = makeMonitorStat("IN", "--");
        outLabel = makeMonitorStat("OUT", "--");
        monitorPanel.add(cpuLabel);
        monitorPanel.add(ramLabel);
        monitorPanel.add(inLabel);
        monitorPanel.add(outLabel);
        bottom.add(monitorPanel, BorderLayout.CENTER);

        JPanel statusBar = new RoundedPanel(12, Theme.BG_PANEL_2);
        statusBar.setLayout(new BorderLayout(10, 0));
        statusBar.setBorder(BorderFactory.createEmptyBorder(8, 12, 8, 12));
        statusLabel = new JLabel("Ready. Enter an IP syntax (regex) and port, then press Start.");
        statusLabel.setFont(FONT_LABEL);
        statusLabel.setForeground(TEXT_MUTED);
        progressBar = new ScanProgressBar();
        progressBar.setPreferredSize(new Dimension(250, 54));
        statusBar.add(statusLabel, BorderLayout.CENTER);
        statusBar.add(progressBar, BorderLayout.EAST);
        bottom.add(statusBar, BorderLayout.SOUTH);

        root.add(bottom, BorderLayout.SOUTH);
        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(root, BorderLayout.CENTER);
    }

    // ================= UI HELPERS =================

    JLabel makeLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(FONT_LABEL);
        l.setForeground(TEXT_MUTED);
        return l;
    }

    JTextField makeField(String text) {
        return makeField(text, 0);
    }

    JTextField makeField(String text, int cols) {
        JTextField f = new JTextField(text);
        f.setColumns(cols);
        f.setBackground(BG_FIELD);
        f.setForeground(TEXT_MAIN);
        f.setCaretColor(TEXT_MAIN);
        f.setFont(FONT_BODY);
        f.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER, 1, true),
                BorderFactory.createEmptyBorder(8, 10, 8, 10)));
        return f;
    }

    void styleCombo(JComboBox<String> combo) {
        combo.setUI(new DarkComboBoxUI());
        combo.setBackground(BG_FIELD);
        combo.setForeground(TEXT_MAIN);
        combo.setFont(FONT_BODY);
        combo.setFocusable(false);
        combo.setOpaque(true);
        combo.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        combo.setRenderer(new DefaultListCellRenderer() {
            @Override
            public Component getListCellRendererComponent(JList<?> list, Object value, int index,
                                                          boolean isSelected, boolean cellHasFocus) {
                JLabel l = (JLabel) super.getListCellRendererComponent(list, value, index, isSelected, cellHasFocus);
                l.setOpaque(true);
                if (isSelected) {
                    l.setBackground(ACCENT_DARK);
                    l.setForeground(Color.WHITE);
                } else {
                    l.setBackground(BG_PANEL_2);
                    l.setForeground(TEXT_MAIN);
                }
                l.setFont(FONT_BODY);
                l.setBorder(BorderFactory.createEmptyBorder(4, 10, 4, 10));
                return l;
            }
        });
    }

    private void styleSpinner(JSpinner spinner) {
        spinner.setBackground(BG_FIELD);
        spinner.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        JComponent editor = spinner.getEditor();
        if (editor instanceof JSpinner.DefaultEditor) {
            JTextField tf = ((JSpinner.DefaultEditor) editor).getTextField();
            tf.setColumns(4);
            tf.setBackground(BG_FIELD);
            tf.setForeground(TEXT_MAIN);
            tf.setFont(FONT_BODY);
            tf.setCaretColor(TEXT_MAIN);
        }
        spinner.setFont(FONT_BODY);
    }

    private JLabel makeStat(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("Segoe UI", Font.BOLD, 13));
        l.setForeground(color);
        return l;
    }

    private JLabel makeMonitorStat(String name, String value) {
        JLabel l = new JLabel(name + ": " + value);
        l.setFont(new Font("Segoe UI", Font.BOLD, 12));
        l.setForeground(TEXT_MAIN);
        l.setToolTipText(name + " usage of this Java process");
        return l;
    }

    // ================= LOGGING =================

    /** Appends a colored line to the on-screen log (marshalled to the EDT). */
    private void appendLog(String prefixColor, String prefixStyle, String text, Color color) {
        SwingUtilities.invokeLater(() -> {
            try {
                String ts = "[" + TIME_FMT.format(new Date()) + "]  ";
                Style tsStyle = logDoc.addStyle("ts", null);
                StyleConstants.setForeground(tsStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), ts, tsStyle);

                Style s = logDoc.addStyle("s", null);
                StyleConstants.setForeground(s, color);
                if (prefixStyle != null && "bold".equals(prefixStyle)) StyleConstants.setBold(s, true);
                logDoc.insertString(logDoc.getLength(), text + "\n", s);
                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    private void logAction(String message) {
        if (logConfig.logActions) {
            appendLog("msg", null, message, TEXT_MAIN);
        }
    }

    /** Simple one-line on-screen log entry. */
    private void logOneLine(String text, Color color) {
        appendLog("line", null, text, color);
    }

    /** Colored status tag + ip:port + optional details, for port results. */
    private void logResult(String ip, int port, String label, Color color, long timeMs) {
        SwingUtilities.invokeLater(() -> {
            try {
                String ts = "[" + TIME_FMT.format(new Date()) + "]  ";
                Style tsStyle = logDoc.addStyle("ts", null);
                StyleConstants.setForeground(tsStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), ts, tsStyle);

                Style tagStyle = logDoc.addStyle("tag", null);
                StyleConstants.setForeground(tagStyle, color);
                StyleConstants.setBold(tagStyle, true);
                logDoc.insertString(logDoc.getLength(), label + "  ", tagStyle);

                Style addrStyle = logDoc.addStyle("addr", null);
                StyleConstants.setForeground(addrStyle, color);
                StyleConstants.setBold(addrStyle, true);
                logDoc.insertString(logDoc.getLength(), ip + ":" + port, addrStyle);

                Style msStyle = logDoc.addStyle("ms", null);
                StyleConstants.setForeground(msStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), "   (" + timeMs + " ms)\n", msStyle);

                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
        // mirror to the current scan log file
        FileLog.get().scan(label + " " + ip + ":" + port + " (" + timeMs + " ms)");
    }

    private void logExternal(String ip, int port, PortScanner.Result result, long timeMs) {
        boolean open = result == PortScanner.Result.OPEN;
        boolean timeout = result == PortScanner.Result.TIMEOUT;
        boolean publicIp = IpUtils.isPublic(ip);
        boolean sameLan = IpUtils.isSameLan(ip);
        String verdict = IpUtils.externalStatus(ip, open, timeout);
        Color color;
        if (sameLan || !publicIp) color = TEXT_MUTED;
        else if (open) color = GREEN;
        else if (timeout) color = YELLOW;
        else color = RED;
        String finalColorHex = toHex(color);
        SwingUtilities.invokeLater(() -> {
            try {
                String ts = "[" + TIME_FMT.format(new Date()) + "]  ";
                Style tsStyle = logDoc.addStyle("ts", null);
                StyleConstants.setForeground(tsStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), ts, tsStyle);

                Style tagStyle = logDoc.addStyle("tag", null);
                StyleConstants.setForeground(tagStyle, BLUE);
                StyleConstants.setBold(tagStyle, true);
                logDoc.insertString(logDoc.getLength(), "\uD83C\uDF0D EXTERNAL:", tagStyle);

                Style verdictStyle = logDoc.addStyle("verdict", null);
                StyleConstants.setForeground(verdictStyle, colorOf(finalColorHex));
                logDoc.insertString(logDoc.getLength(), "  " + ip + ":" + port + " — " + verdict + "   (" + timeMs + " ms)\n", verdictStyle);

                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    private void logMcResult(String ip, int port, McProbe.Result probe) {
        SwingUtilities.invokeLater(() -> {
            try {
                String ts = "[" + TIME_FMT.format(new Date()) + "]  ";
                Style tsStyle = logDoc.addStyle("ts", null);
                StyleConstants.setForeground(tsStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), ts, tsStyle);

                Style tagStyle = logDoc.addStyle("tag", null);
                StyleConstants.setForeground(tagStyle, GREEN);
                StyleConstants.setBold(tagStyle, true);
                logDoc.insertString(logDoc.getLength(), "\u2705 MC-SERVER  ", tagStyle);

                Style addrStyle = logDoc.addStyle("addr", null);
                StyleConstants.setForeground(addrStyle, GREEN);
                StyleConstants.setBold(addrStyle, true);
                logDoc.insertString(logDoc.getLength(), ip + ":" + port, addrStyle);

                Style msStyle = logDoc.addStyle("ms", null);
                StyleConstants.setForeground(msStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), "   (" + probe.latencyMs + " ms)\n", msStyle);

                Style detStyle = logDoc.addStyle("det", null);
                StyleConstants.setForeground(detStyle, TEXT_MAIN);
                String version = probe.version.isEmpty() ? "?" : probe.version;
                logDoc.insertString(logDoc.getLength(),
                        "     \uD83C\uDFAE Version: " + version
                        + (probe.brand.isEmpty() ? "" : "   \uD83C\uDFAF Brand: " + probe.brand)
                        + "   \uD83D\uDC64 Players: " + probe.online + "/" + probe.max
                        + (probe.hasFavicon ? "   \uD83D\uDDBC Icon" : "") + "\n", detStyle);
                if (!probe.motd.isEmpty()) {
                    Style motdStyle = logDoc.addStyle("motd", null);
                    StyleConstants.setForeground(motdStyle, YELLOW);
                    logDoc.insertString(logDoc.getLength(), "     \uD83D\uDCE2 " + probe.motd + "\n", motdStyle);
                }
                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
        FileLog.get().scan("MC-SERVER " + ip + ":" + port + " version=" + probe.version
                + " brand=" + probe.brand + " players=" + probe.online + "/" + probe.max);
    }

    private void clearAll() {
        clearLog();
        openResults.clear();
        mcResults.clear();
        openCount.set(0);
        closedCount.set(0);
        scannedNow = 0;
        externalCount.set(0);
        updateStats();
        setStatus("Log cleared");
    }

    private void clearLog() {
        SwingUtilities.invokeLater(() -> {
            try {
                logDoc.remove(0, logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    private void setStatus(String text) {
        statusLabel.setText(text);
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            totalLabel.setText("Total: " + totalTargets);
            openLabel.setText("Open: " + openCount.get());
            externalLabel.setText("External: " + externalCount.get());
            closedLabel.setText("Closed: " + closedCount.get());
        });
    }

    private void refreshPerf() {
        try {
            PerfMonitor.tickRates();
            double cpu = PerfMonitor.getProcessCpuLoad();
            cpuLabel.setText("CPU: " + (cpu < 0 ? "--" : (int) (cpu * 100) + "%"));
            cpuLabel.setForeground(cpu < 0 ? TEXT_MUTED : ACCENT);
            ramLabel.setText("RAM: " + PerfMonitor.getHeapUsedMB() + " / " + PerfMonitor.getHeapTotalMB() + " MB");
            inLabel.setText("IN: " + formatRate(PerfMonitor.getRecvRate()) + "  (tot "
                    + formatBytesTotal(PerfMonitor.getTotalRecv()) + ")");
            inLabel.setForeground(GREEN);
            outLabel.setText("OUT: " + formatRate(PerfMonitor.getSentRate()) + "  (tot "
                    + formatBytesTotal(PerfMonitor.getTotalSent()) + ")");
            outLabel.setForeground(BLUE);
        } catch (Throwable ignored) {
        }
    }

    private static String formatRate(long bytesPerSec) {
        if (bytesPerSec >= 1_000_000L) return String.format(Locale.US, "%.1f MB/s", bytesPerSec / 1_000_000.0);
        if (bytesPerSec >= 1_000L) return String.format(Locale.US, "%.1f KB/s", bytesPerSec / 1_000.0);
        return bytesPerSec + " B/s";
    }

    private static String formatBytesTotal(long bytes) {
        if (bytes >= 1_000_000L) return String.format(Locale.US, "%.1f MB", bytes / 1_000_000.0);
        if (bytes >= 1_000L) return String.format(Locale.US, "%.1f KB", bytes / 1_000.0);
        return bytes + " B";
    }

    // ================= INPUT MODE / SCALE =================

    void applySyntaxMode() {
        ipPatternField.setVisible("Single".equals(syntaxMode));
        listScroll.setVisible("List".equals(syntaxMode));
        fileFieldScroll.setVisible("File".equals(syntaxMode));
        browseButton.setVisible("File".equals(syntaxMode));
        updateScale();
    }

    private void choosePatternFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select patterns file (one regex / CIDR per line)");
        chooser.setCurrentDirectory(new File(AppPaths.home().toString()));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            fileField.setText(chooser.getSelectedFile().getAbsolutePath());
            updateScale();
        }
    }

    private void updateScale() {
        if ("File".equals(syntaxMode)) {
            String path = fileField.getText().trim();
            try {
                if (path.isEmpty() || !Files.exists(Paths.get(path))) {
                    scalePanel.setState(false, 0);
                    return;
                }
            } catch (Exception ex) {
                scalePanel.setState(false, 0);
                return;
            }
        }
        List<String> lines = currentPatternLines();
        List<String> conv = convertPatternLines(lines);
        boolean ok = conv != null && IpPattern.structureOkAll(conv, useCidr);
        long count = ok ? IpPattern.countIpsAll(conv, useCidr) : 0;
        scalePanel.setState(ok, count);
    }

    private void updateThreadScale() {
        int threads = (Integer) netSpinner.getValue();
        threadScale.setValue(threads);
    }

    private List<String> currentPatternLines() {
        List<String> lines = new ArrayList<>();
        if ("List".equals(syntaxMode)) {
            for (String l : listArea.getText().split("\n")) {
                String t = l.trim();
                if (!t.isEmpty()) lines.add(t);
            }
        } else if ("File".equals(syntaxMode)) {
            String path = fileField.getText().trim();
            if (!path.isEmpty()) {
                try {
                    for (String l : Files.readAllLines(Paths.get(path))) {
                        String t = l.trim();
                        if (!t.isEmpty()) lines.add(t);
                    }
                } catch (Exception ignored) {
                }
            }
        } else {
            String t = ipPatternField.getText().trim();
            if (!t.isEmpty()) lines.add(t);
        }
        return lines;
    }

    private List<String> convertPatternLines(List<String> raw) {
        List<String> out = new ArrayList<>();
        if (raw == null) return null;
        for (String line : raw) {
            String conv = SyntaxConv.toRegex(line, syntaxType, useCidr);
            if (conv == null) return null;
            out.add(conv);
        }
        return out;
    }

    // ================= SCAN LOGIC =================

    private void startScan() {
        if ("File".equals(syntaxMode)) {
            String path = fileField.getText().trim();
            boolean ok = true;
            try {
                if (path.isEmpty() || !Files.exists(Paths.get(path))) ok = false;
            } catch (Exception ex) {
                ok = false;
            }
            if (!ok) {
                JOptionPane.showMessageDialog(this,
                        "Patterns file not found: " + (path.isEmpty() ? "(empty)" : path)
                                + "\nChoose the file with the folder icon, or enter a valid path.",
                        "Input error", JOptionPane.ERROR_MESSAGE);
                return;
            }
        }
        List<String> patternLines = currentPatternLines();
        String portSpec = portField.getText().trim();

        if (patternLines.isEmpty() || portSpec.isEmpty()) {
            JOptionPane.showMessageDialog(this,
                    "Fill in the IP syntax and port.\n"
                            + "Single: ^95\\.31\\.\\d{1,3}\\.\\d$  or  95\\.31\\.0\\.0/16\n"
                            + "List: several patterns, one per line\n"
                            + "File: path to a text file with one pattern per line\n"
                            + "Port: 2000  or  2000-2010",
                    "Input error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        List<String> converted = convertPatternLines(patternLines);
        if (converted == null) {
            String hint;
            switch (syntaxType) {
                case "ip": hint = "Type ip needs a full IP, e.g. 95.31.158.9" + (useCidr ? "  or  95.31.158.9/24" : ""); break;
                case "wildcard": hint = "Type wildcard: * means any number, e.g. 95.31.***.*" + (useCidr ? "  or  95.31.***.*/8" : ""); break;
                default: hint = "Type regex: Java regex for IPv4 (4 octets), e.g. ^95\\.31\\.\\d{1,3}\\.\\d$";
            }
            JOptionPane.showMessageDialog(this,
                    "Invalid IP syntax for type " + syntaxType + ".\n" + hint,
                    "Input error", JOptionPane.ERROR_MESSAGE);
            return;
        }
        patternLines = converted;
        String portErr = validatePortSpec(portSpec);
        if (portErr != null) {
            JOptionPane.showMessageDialog(this, portErr, "Input error", JOptionPane.ERROR_MESSAGE);
            return;
        }

        int timeout;
        try {
            timeout = Integer.parseInt(timeoutField.getText().trim());
            if (timeout < 50 || timeout > 60000) throw new NumberFormatException();
        } catch (NumberFormatException ex) {
            JOptionPane.showMessageDialog(this, "Timeout must be a number between 50 and 60000 ms");
            return;
        }

        int parseThreads = (Integer) parseSpinner.getValue();
        int genThreads = (Integer) genSpinner.getValue();
        int netThreads = (Integer) netSpinner.getValue();

        long totalIps = IpPattern.countIpsAll(patternLines, useCidr);
        if (totalIps == 0) {
            if (IpPattern.structureOkAll(patternLines, useCidr)) {
                JOptionPane.showMessageDialog(this,
                        "No IPs matched the syntax.\nNothing in the 0-255 range per octet matches it.");
            } else {
                JOptionPane.showMessageDialog(this,
                        "Invalid IP syntax.\n"
                                + "Type " + syntaxType + ", CIDR " + (useCidr ? "on" : "off") + ".\n"
                                + "ip:       95.31.158.9" + (useCidr ? "  or  95.31.158.9/24" : "") + "\n"
                                + "wildcard: 95.31.***.*  (* = any number)" + (useCidr ? "  or  95.31.***.*/8" : "") + "\n"
                                + "regex:    ^95\\.31\\.\\d{1,3}\\.\\d$  or  95\\.31\\.0\\.0/16");
            }
            return;
        }

        int[] ports = PortScanner.parsePorts(portSpec);
        int startPort = ports[0];
        int endPort = ports[1];

        totalTargets = totalIps * (long) (endPort - startPort + 1);
        if (totalTargets > 100_000_000L) {
            int choice = JOptionPane.showConfirmDialog(this,
                    "This scan covers " + String.format(Locale.US, "%,d", totalTargets) + " targets\n"
                            + "(" + String.format(Locale.US, "%,d", totalIps) + " IPs x "
                            + (endPort - startPort + 1) + " ports).\n"
                            + "It will take a very long time. Continue?",
                    "Large scan", JOptionPane.YES_NO_OPTION, JOptionPane.WARNING_MESSAGE);
            if (choice != JOptionPane.YES_OPTION) {
                return;
            }
        }
        List<List<List<Integer>>> blocks = IpPattern.blocksAll(patternLines, useCidr);
        openCount.set(0);
        closedCount.set(0);
        scannedNow = 0;
        externalCount.set(0);
        lastProgressPosted = 0;
        scanStartNanos = System.nanoTime();
        statusLabel.setForeground(Color.WHITE);
        PerfMonitor.reset();

        openResults.clear();
        mcResults.clear();
        progressBar.setProgress(0);

        String portDesc = startPort == endPort ? String.valueOf(startPort) : startPort + "-" + endPort;
        logAction("");
        logAction("═══════════════════ SCANNING STARTED ═══════════════════");
        logAction("Mode: " + (isMcMode() ? "Minecraft (mcprobe)" : "Telnet (TCP)")
                + "   |   Syntax: type=" + syntaxType + ", input=" + syntaxMode.toLowerCase()
                + ", CIDR=" + (useCidr ? "on" : "off")
                + "   |   " + patternLines.size() + " pattern(s)   (" + totalIps + " addresses)");
        logAction("Port: " + portDesc + "   (targets: " + totalTargets + ")");
        logAction("Timeout: " + timeout + " ms,  CPU threads: " + parseThreads + " parse / " + genThreads + " gen,  network: " + netThreads);
        if (logConfig.external) {
            logAction("Status 2 enabled: public IP + open port = reachable from outside");
        }
        updateStats();

        saveSettings();

        // Start a dedicated scan log file for this run.
        FileLog.get().beginScan();
        FileLog.get().scanMode(isMcMode() ? "Minecraft" : "Telnet", syntaxType, syntaxMode, useCidr, totalIps);
        FileLog.get().scan("Port: " + portDesc + "  targets: " + totalTargets + "  timeout: " + timeout + "ms");

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        exportButton.setEnabled(false);

        if (isMcMode()) {
            startMcScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads);
        } else {
            startTelnetScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads);
        }
    }

    private void startTelnetScan(List<List<List<Integer>>> blocks, int startPort, int endPort, int timeout,
                                 int parseThreads, int genThreads, int netThreads) {
        PortScanner ps = new PortScanner();
        scanner = ps;
        ps.startScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads, new AbstractScanner.Listener<PortScanner.Raw>() {
            @Override
            public void onResult(String ip, int port, PortScanner.Raw raw) {
                PortScanner.Result result = raw.result;
                if (result == PortScanner.Result.OPEN) {
                    openCount.incrementAndGet();
                    openResults.add(ip + ":" + port);
                    if (logConfig.logOpen) logResult(ip, port, "\u2705 OPEN", GREEN, raw.timeMs);
                    if (logConfig.external && IpUtils.isPublic(ip) && !IpUtils.isSameLan(ip)) {
                        externalCount.incrementAndGet();
                    }
                } else {
                    if (result == PortScanner.Result.CLOSED) {
                        closedCount.incrementAndGet();
                        if (logConfig.logClosed) logResult(ip, port, "\u274C CLOSED", RED, raw.timeMs);
                    } else if (result == PortScanner.Result.TIMEOUT) {
                        if (logConfig.logTimeout) logResult(ip, port, "\u23F3 TIMEOUT", YELLOW, raw.timeMs);
                    } else {
                        if (logConfig.logError) logResult(ip, port, "\u2753 ERROR", GRAY, raw.timeMs);
                    }
                }
                if (logConfig.external) {
                    logExternal(ip, port, result, raw.timeMs);
                }
            }

            @Override
            public void onProgress(long scanned, long total) {
                scannedNow = (int) Math.min(scanned, Integer.MAX_VALUE);
                long last = lastProgressPosted;
                if (scanned != total && scanned - last < Math.max(1, total / 500)) {
                    return;
                }
                lastProgressPosted = scanned;
                long left = total - scanned;
                double pct = total == 0 ? 0 : scanned * 100.0 / total;
                long elapsedMs = (System.nanoTime() - scanStartNanos) / 1_000_000L;
                long etaMs = (scanned > 0 && elapsedMs > 0 && left > 0)
                        ? (long) (left * (double) elapsedMs / scanned) : 0;
                double finalPct = pct;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setProgress(finalPct);
                    setStatus("Checked: " + fmtNum(scanned) + "  |  Left: " + fmtNum(left)
                            + "  |  ETA " + formatEta(etaMs));
                });
                updateStats();
            }

            @Override
            public void onFinished() {
                SwingUtilities.invokeLater(() -> {
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    exportButton.setEnabled(true);
                    progressBar.setProgress(100);
                    updateStats();
                    String ext = logConfig.external ? "  |  External: " + externalCount.get() : "";
                    setStatus("Done. Open ports: " + openCount.get() + ext);
                    statusLabel.setForeground(TEXT_MUTED);
                    logAction("");
                    logAction("═══════════════════ SCANNING FINISHED ═══════════════════");
                    logAction("Open ports: " + openCount.get() + "  |  Closed: " + closedCount.get() + ext);
                    FileLog.get().closeScan();
                });
            }
        });
    }

    private void startMcScan(List<List<List<Integer>>> blocks, int startPort, int endPort, int timeout,
                             int parseThreads, int genThreads, int netThreads) {
        McProbeScanner ms = new McProbeScanner();
        scanner = ms;
        ms.startScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads, new AbstractScanner.Listener<McProbe.Result>() {
            @Override
            public void onResult(String ip, int port, McProbe.Result probe) {
                if (probe.success) {
                    if (!McFilters.passes(probe, mcFilters)) {
                        return;
                    }
                    openCount.incrementAndGet();
                    String key = ip + ":" + port;
                    openResults.add(key);
                    mcResults.put(key, probe);
                    logMcResult(ip, port, probe);
                    if (logConfig.external && IpUtils.isPublic(ip) && !IpUtils.isSameLan(ip)) {
                        externalCount.incrementAndGet();
                    }
                } else {
                    closedCount.incrementAndGet();
                    if (logConfig.logClosed) logResult(ip, port, "\u274C CLOSED", RED, probe.latencyMs);
                }
                if (logConfig.external) {
                    logExternal(ip, port, probe.success ? PortScanner.Result.OPEN : PortScanner.Result.CLOSED, probe.latencyMs);
                }
            }

            @Override
            public void onProgress(long scanned, long total) {
                scannedNow = (int) Math.min(scanned, Integer.MAX_VALUE);
                long last = lastProgressPosted;
                if (scanned != total && scanned - last < Math.max(1, total / 500)) {
                    return;
                }
                lastProgressPosted = scanned;
                long left = total - scanned;
                double pct = total == 0 ? 0 : scanned * 100.0 / total;
                long elapsedMs = (System.nanoTime() - scanStartNanos) / 1_000_000L;
                long etaMs = (scanned > 0 && elapsedMs > 0 && left > 0)
                        ? (long) (left * (double) elapsedMs / scanned) : 0;
                double finalPct = pct;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setProgress(finalPct);
                    setStatus("Checked: " + fmtNum(scanned) + "  |  Left: " + fmtNum(left)
                            + "  |  ETA " + formatEta(etaMs));
                });
                updateStats();
            }

            @Override
            public void onFinished() {
                SwingUtilities.invokeLater(() -> {
                    startButton.setEnabled(true);
                    stopButton.setEnabled(false);
                    exportButton.setEnabled(true);
                    progressBar.setProgress(100);
                    updateStats();
                    String ext = logConfig.external ? "  |  External: " + externalCount.get() : "";
                    setStatus("Done. MC servers found: " + openCount.get() + ext);
                    statusLabel.setForeground(TEXT_MUTED);
                    logAction("");
                    logAction("═══════════════════ SCANNING FINISHED ═══════════════════");
                    logAction("MC servers found: " + openCount.get() + "  |  No response: " + closedCount.get() + ext);
                    FileLog.get().closeScan();
                });
            }
        });
    }

    private void stopScan() {
        if (scanner != null) scanner.stop();
        logAction("--- Scan stopped by user ---");
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        exportButton.setEnabled(true);
        setStatus("Stopped. Found: " + openCount.get());
        statusLabel.setForeground(TEXT_MUTED);
        FileLog.get().closeScan();
    }

    private void exportResults() {
        if (openResults.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No results to export.");
            return;
        }
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save results");
        chooser.setSelectedFile(new File("results_" + TIME_FMT.format(new Date()).replace(":", "-") + ".txt"));
        chooser.setCurrentDirectory(new File(AppPaths.home().toString()));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".txt")) {
                file = new File(file.getParentFile(), file.getName() + ".txt");
            }
            Export.ExportParams p = new Export.ExportParams();
            p.mcMode = isMcMode();
            p.syntaxType = syntaxType;
            p.syntaxMode = syntaxMode;
            p.useCidr = useCidr;
            p.patternDesc = patternLinesForExport();
            p.portSpec = portField.getText().trim();
            p.external = logConfig.external;
            p.externalCount = externalCount.get();
            p.openResults = openResults;
            p.mcResults = mcResults;
            String content = Export.build(p);
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write(content);
                logAction("\uD83D\uDCC4 Exported: " + file.getAbsolutePath());
                setStatus("Results saved: " + file.getName());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Save error: " + ex.getMessage());
            }
        }
    }

    private String patternLinesForExport() {
        if ("File".equals(syntaxMode)) {
            return fileField.getText().trim();
        }
        List<String> lines = currentPatternLines();
        return lines.isEmpty() ? "" : String.join(" ; ", lines);
    }

    private boolean isMcMode() {
        return modeCombo != null && ((String) modeCombo.getSelectedItem()).contains("Minecraft");
    }

    private static String validatePortSpec(String spec) {
        String s = spec.trim();
        String[] parts = s.split("-");
        if (parts.length > 2) {
            return "Invalid port range (too many '-').\nUse: 2000  or  2000-2010";
        }
        for (String p : parts) {
            String t = p.trim();
            if (t.isEmpty()) {
                return "Invalid port: '" + s + "'.\nUse: 2000  or  2000-2010";
            }
            int v;
            try {
                v = Integer.parseInt(t);
            } catch (NumberFormatException e) {
                return "Invalid port: '" + t + "'.\nMust be a number between 1 and 65535.";
            }
            if (v < 1 || v > 65535) {
                return "Port " + v + " is out of range.\nPorts must be between 1 and 65535.";
            }
        }
        return null;
    }

    private static String fmtNum(long n) {
        return String.format(Locale.US, "%,d", n);
    }

    private static String formatEta(long ms) {
        long sec = ms / 1000;
        long days = sec / 86400;
        sec %= 86400;
        long h = sec / 3600;
        sec %= 3600;
        long m = sec / 60;
        long s = sec % 60;
        if (days > 0) {
            return String.format(Locale.US, "%dd %02d:%02d:%02d", days, h, m, s);
        }
        return String.format(Locale.US, "%02d:%02d:%02d", h, m, s);
    }

    private static String toHex(Color c) {
        return String.format("#%02x%02x%02x", c.getRed(), c.getGreen(), c.getBlue());
    }

    private static Color colorOf(String hex) {
        return Color.decode(hex);
    }

    // ================= SETTINGS (SQLite) =================

    private void loadSettings() {
        AppDb db = AppDb.get();
        String p0 = db.get("syntax.pattern", null);
        if (p0 != null) {
            if ("List".equals(syntaxMode)) listArea.setText(p0.replace("\u0001", "\n"));
            else if ("File".equals(syntaxMode)) fileField.setText(p0);
            else ipPatternField.setText(p0);
        }
        String port = db.get("syntax.port", null);
        if (port != null) portField.setText(port);
        String timeout = db.get("syntax.timeout", null);
        if (timeout != null) {
            try { timeoutField.setText(timeout); } catch (RuntimeException ignored) { }
        }
        try { parseSpinner.setValue(clampInt(db.getInt("syntax.parseThreads", (Integer) parseSpinner.getValue()), parseSpinner)); } catch (RuntimeException ignored) { }
        try { genSpinner.setValue(clampInt(db.getInt("syntax.genThreads", (Integer) genSpinner.getValue()), genSpinner)); } catch (RuntimeException ignored) { }
        try { netSpinner.setValue(clampInt(db.getInt("syntax.netThreads", (Integer) netSpinner.getValue()), netSpinner)); } catch (RuntimeException ignored) { }

        String mode = db.get("syntax.inputMode", null);
        if (mode != null) {
            if ("List".equals(mode)) syntaxMode = "List";
            else if ("File".equals(mode)) syntaxMode = "File";
            else syntaxMode = "Single";
        }
        String type = db.get("syntax.type", null);
        if (type != null && ("ip".equals(type) || "wildcard".equals(type) || "regex".equals(type))) {
            syntaxType = type;
        }
        useCidr = db.getBool("syntax.cidr", useCidr);
        int modeIdx = db.getInt("syntax.modeIndex", modeCombo.getSelectedIndex());
        modeCombo.setSelectedIndex(clampInt(modeIdx, 0, modeCombo.getItemCount() - 1));

        externalCheck.setSelected(logConfig.external);
        applySyntaxMode();
        updateThreadScale();
        updateScale();
    }

    void saveSettings() {
        AppDb.Adapter a = AppDb.get().adapter();
        String p0;
        if ("List".equals(syntaxMode)) {
            p0 = listArea.getText().replace("\n", "\u0001");
        } else if ("File".equals(syntaxMode)) {
            p0 = fileField.getText().trim();
        } else {
            p0 = ipPatternField.getText().trim();
        }
        a.set("syntax.pattern", p0);
        a.set("syntax.port", portField.getText().trim());
        a.set("syntax.timeout", timeoutField.getText().trim());
        a.setInt("syntax.parseThreads", (Integer) parseSpinner.getValue());
        a.setInt("syntax.genThreads", (Integer) genSpinner.getValue());
        a.setInt("syntax.netThreads", (Integer) netSpinner.getValue());
        a.setBool("syntax.cidr", useCidr);
        a.set("syntax.inputMode", syntaxMode.toLowerCase());
        a.set("syntax.type", syntaxType);
        a.setInt("syntax.modeIndex", modeCombo.getSelectedIndex());
        logConfig.save();
    }

    private static int clampInt(int v, JSpinner spinner) {
        SpinnerNumberModel m = (SpinnerNumberModel) spinner.getModel();
        return Math.max(((Number) m.getMinimum()).intValue(),
                Math.min(((Number) m.getMaximum()).intValue(), v));
    }

    private static int clampInt(int v, int min, int max) {
        return Math.max(min, Math.min(max, v));
    }

    // ================= ACCESSORS FOR DIALOGS =================

    LogConfig getLogConfig() {
        return logConfig;
    }

    String getSyntaxType() { return syntaxType; }
    void setSyntaxType(String t) { this.syntaxType = t; }
    String getSyntaxMode() { return syntaxMode; }
    void setSyntaxMode(String m) { this.syntaxMode = m; }
    boolean isUseCidr() { return useCidr; }
    void setUseCidr(boolean c) { this.useCidr = c; }

    private void openLogSettings() {
        LogSettingsDialog d = new LogSettingsDialog(this);
        d.setLocationRelativeTo(this);
        d.setVisible(true);
    }

    private void openIpSettings() {
        IpSettingsDialog d = new IpSettingsDialog(this);
        d.setLocationRelativeTo(this);
        d.setVisible(true);
    }
}