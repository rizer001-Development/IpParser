import javax.swing.*;
import javax.swing.border.EmptyBorder;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.plaf.ColorUIResource;
import javax.swing.plaf.basic.BasicArrowButton;
import javax.swing.plaf.basic.BasicComboBoxUI;
import javax.swing.text.*;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.awt.geom.RoundRectangle2D;
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

/**
 * IP Parser - portable IP-range TCP port scanner.
 * Dark-themed Swing GUI with a colored log in the center.
 */
public class IpParserGUI extends JFrame {

    // ================= DARK THEME PALETTE =================
    private static final Color BG_ROOT        = new Color(17, 18, 26);
    private static final Color BG_PANEL       = new Color(27, 28, 40);
    private static final Color BG_PANEL_2     = new Color(32, 34, 48);
    private static final Color BG_FIELD       = new Color(40, 42, 58);
    private static final Color BG_LOG         = new Color(14, 15, 22);
    private static final Color BORDER         = new Color(58, 61, 82);
    private static final Color BORDER_FOCUS   = new Color(124, 108, 255);
    private static final Color ACCENT         = new Color(124, 108, 255);
    private static final Color ACCENT_DARK    = new Color(94, 78, 215);
    private static final Color TEXT_MAIN      = new Color(226, 227, 240);
    private static final Color TEXT_MUTED     = new Color(140, 143, 165);
    private static final Color GREEN          = new Color(88, 230, 140);
    private static final Color GREEN_DARK     = new Color(38, 140, 76);
    private static final Color RED            = new Color(255, 105, 105);
    private static final Color RED_DARK       = new Color(178, 58, 58);
    private static final Color YELLOW         = new Color(250, 200, 90);
    private static final Color GRAY           = new Color(168, 171, 190);
    private static final Color BLUE           = new Color(94, 160, 255);

    private static final Font FONT_BODY    = new Font("Segoe UI", Font.PLAIN, 13);
    private static final Font FONT_MONO    = new Font("Consolas", Font.PLAIN, 13);
    private static final Font FONT_TITLE   = new Font("Segoe UI", Font.BOLD, 20);
    private static final Font FONT_BTN     = new Font("Segoe UI", Font.BOLD, 13);
    private static final Font FONT_LABEL   = new Font("Segoe UI", Font.PLAIN, 12);

    // ================= COMPONENTS =================
    private JTextField ipPatternField;
    private JTextField fileField;
    private JScrollPane fileFieldScroll;
    private RoundedButton syntaxSettingsButton; // opens IP parsing settings (type / input mode / CIDR)
    private JButton browseButton;
    private JTextArea listArea;
    private JScrollPane listScroll;
    private JTextField portField;

    // ---- IP parsing settings (Syntax gear button) ----
    private String syntaxType = "regex";    // ip / wildcard / regex
    private String syntaxMode = "Single";   // Single / List / File
    private boolean useCidr = true;          // CIDR interpretation on/off
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
    private JCheckBox externalCheck; // Status 2 toggle - now controlled from Log Settings dialog

    // ---- Log settings state (Log Settings dialog) ----
    // Read from scanner worker threads, written on the EDT (dialog Apply) -> volatile.
    private volatile boolean logOpen = true;
    private volatile boolean logClosed = false;
    private volatile boolean logTimeout = false;
    private volatile boolean logError = false;
    private volatile boolean logActions = true;
    private volatile boolean mcFilterOnline = false;
    private volatile String mcFilterOnlineOp = "is";
    private volatile String mcFilterOnlineVal = "";
    private volatile boolean mcFilterVersion = false;
    private volatile String mcFilterVersionOp = "is";
    private volatile String mcFilterVersionVal = "";
    private volatile boolean mcFilterBrand = false;
    private volatile String mcFilterBrandVal = "";
    private volatile boolean mcFilterMotd = false;
    private volatile String mcFilterMotdVal = "";
    private volatile boolean mcFilterPlayers = false;
    private volatile String mcFilterPlayersVal = "";
    private JLabel externalLabel;
    private JComboBox<String> modeCombo;
    private IpScale scalePanel;
    private ThreadScale threadScale;
    private JLabel cpuLabel;
    private JLabel ramLabel;
    private JLabel inLabel;
    private JLabel outLabel;

    private PortScanner scanner;
    private McProbeScanner mcScanner;
    private final List<String> openResults = new CopyOnWriteArrayList<>();
    private final Map<String, McProbe.Result> mcResults = new ConcurrentHashMap<>();

    private static final SimpleDateFormat TIME_FMT = new SimpleDateFormat("HH:mm:ss");

    private volatile long totalTargets = 0;
    private volatile int openCount = 0;
    private volatile int closedCount = 0;
    private volatile int scannedNow = 0;
    private volatile int externalCount = 0;
    private volatile long lastProgressPosted = 0;
    private volatile long scanStartNanos = 0;

    public IpParserGUI() {
        super("IP Parser - IP and port scanner");
        setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent e) {
                if (scanner != null) scanner.stop();
                if (mcScanner != null) mcScanner.stop();
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
        new Timer(1000, e -> refreshPerf()).start();
    }

    private void buildUi() {
        JPanel root = new JPanel(new BorderLayout(0, 10));
        root.setBackground(BG_ROOT);
        root.setBorder(new EmptyBorder(12, 12, 12, 12));

        // ---- Header ----
        JPanel header = new RoundedPanel(14, BG_PANEL);
        header.setLayout(new BorderLayout(10, 0));
        header.setBorder(new EmptyBorder(14, 18, 14, 18));

        JPanel titleBlock = new JPanel(new FlowLayout(FlowLayout.LEFT, 12, 0));
        titleBlock.setOpaque(false);
        JLabel logo = new JLabel("\uD83C\uDF10");
        logo.setFont(new Font("Segoe UI Emoji", Font.PLAIN, 30));
        JPanel titleText = new JPanel(new GridLayout(2, 1));
        titleText.setOpaque(false);
        JLabel title = new JLabel("IP Parser");
        title.setFont(FONT_TITLE);
        title.setForeground(TEXT_MAIN);
        JLabel subtitle = new JLabel("Pattern-based IP scanner and port checker");
        subtitle.setFont(FONT_LABEL);
        subtitle.setForeground(TEXT_MUTED);
        titleText.add(title);
        titleText.add(subtitle);
        titleBlock.add(logo);
        titleBlock.add(titleText);
        header.add(titleBlock, BorderLayout.WEST);

        JPanel stats = new JPanel(new FlowLayout(FlowLayout.RIGHT, 16, 6));
        stats.setOpaque(false);
        totalLabel = makeStat("Total: 0", TEXT_MUTED);
        openLabel = makeStat("Open: 0", GREEN);
        externalLabel = makeStat("External: 0", BLUE);
        closedLabel = makeStat("Closed: 0", RED);
        stats.add(totalLabel);
        stats.add(openLabel);
        stats.add(externalLabel);
        stats.add(closedLabel);
        header.add(stats, BorderLayout.EAST);

        root.add(header, BorderLayout.NORTH);

        // ---- Settings panel ----
        JPanel settings = new RoundedPanel(14, BG_PANEL);
        settings.setLayout(new GridBagLayout());
        settings.setBorder(new EmptyBorder(14, 18, 14, 18));
        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 6, 5, 6);
        gbc.fill = GridBagConstraints.HORIZONTAL;

        // Row 0: Syntax mode (Single/List/File) + input + live IP-count scale (compact)
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
        listArea.setBorder(new EmptyBorder(6, 10, 6, 10));
        listArea.setToolTipText("Several regexes / CIDR blocks, one per line.\nEach line is scanned; the scale sums the IPs of all lines.");
        listScroll = new JScrollPane(listArea);
        listScroll.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        listScroll.getViewport().setBackground(BG_FIELD);
        syntaxRow.add(listScroll);

        fileField = makeField("", 13);
        fileField.setToolTipText("Patterns file path - long paths scroll inside the field");
        fileField.setBorder(new EmptyBorder(8, 10, 8, 10));
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

        // Settings button: opens IP parsing settings (type / input mode / CIDR)
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

        // Show only the input widget of the active mode (keeps the row compact)
        applySyntaxMode();

        // Row 1: Port / range + Timeout (label, field, label, field tightly packed)
        gbc.gridx = 0; gbc.gridy = 1; gbc.gridwidth = 4; gbc.weightx = 1.0;
        gbc.fill = GridBagConstraints.HORIZONTAL; gbc.insets = new Insets(5, 6, 5, 6);
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

        // Row 2: CPU (Parse/Gen, max = CPU cores) + network (Net, max 1024) threads
        gbc.gridx = 0; gbc.gridy = 2; gbc.insets = new Insets(5, 6, 5, 6);
        settings.add(makeLabel("Threads"), gbc);
        gbc.gridx = 1; gbc.weightx = 0.3;
        JPanel threadFields = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        threadFields.setOpaque(false);
        int cores = Runtime.getRuntime().availableProcessors();
        JLabel pLbl = new JLabel("Parse:");
        pLbl.setFont(FONT_LABEL); pLbl.setForeground(TEXT_MUTED);
        pLbl.setToolTipText("CPU threads that process results (max = CPU cores: " + cores + ")");
        threadFields.add(pLbl);
        parseSpinner = new JSpinner(new SpinnerNumberModel(cores, 1, cores, 1));
        styleSpinner(parseSpinner);
        parseSpinner.setToolTipText("CPU threads that process results (max " + cores + " = CPU cores)");
        threadFields.add(parseSpinner);
        JLabel gLbl = new JLabel("Gen:");
        gLbl.setFont(FONT_LABEL); gLbl.setForeground(TEXT_MUTED);
        gLbl.setToolTipText("CPU threads that generate IPs from regex/CIDR (max = CPU cores: " + cores + ")");
        threadFields.add(gLbl);
        genSpinner = new JSpinner(new SpinnerNumberModel(Math.min(4, cores), 1, cores, 1));
        styleSpinner(genSpinner);
        genSpinner.setToolTipText("CPU threads that generate IPs (max " + cores + " = CPU cores)");
        threadFields.add(genSpinner);
        JLabel nLbl = new JLabel("Net:");
        nLbl.setFont(FONT_LABEL); nLbl.setForeground(TEXT_MUTED);
        nLbl.setToolTipText("Network threads that open connections - separate from CPU threads (max 1024)");
        threadFields.add(nLbl);
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

        // Row 3: Mode selector (full width)
        gbc.gridx = 0; gbc.gridy = 3; gbc.insets = new Insets(5, 6, 5, 6);
        settings.add(makeLabel("Mode"), gbc);
        gbc.gridx = 1; gbc.gridwidth = 3; gbc.weightx = 1.0;
        modeCombo = new JComboBox<>(new String[]{"Telnet (TCP port)", "Minecraft (mcprobe)"});
        styleCombo(modeCombo);
        modeCombo.setToolTipText("Telnet: plain TCP port check.\nMinecraft: ping via Server List Ping protocol\n(version, MOTD, players online/max).");
        settings.add(modeCombo, gbc);
        gbc.gridwidth = 1; gbc.weightx = 0;

        // Row 4: port format hint (Status 2 toggle moved to the Log Settings dialog)
        gbc.gridx = 0; gbc.gridy = 4; gbc.gridwidth = 4; gbc.insets = new Insets(8, 6, 2, 6);
        JLabel portHint = new JLabel("\uD83D\uDD11 Port format:  2000  (single)  or  2000-2010  (range)");
        portHint.setFont(FONT_LABEL);
        portHint.setForeground(TEXT_MUTED);
        settings.add(portHint, gbc);
        gbc.gridwidth = 1;

        // Status 2 toggle: created here but NOT added to the layout - it is
        // controlled from the Log Settings dialog (gear button near the log).
        externalCheck = new JCheckBox("Status 2");
        externalCheck.setOpaque(false);
        externalCheck.setSelected(false);
        externalCheck.setToolTipText("Status 2: show port reachability from outside (public IP / port forwarding).\n"
                + "Configured in Log Settings (gear button next to the log).");

        // Live update of the IP-count scale as the user types
        DocumentListener scaleListener = new DocumentListener() {
            @Override
            public void insertUpdate(DocumentEvent e) {
                updateScale();
            }

            @Override
            public void removeUpdate(DocumentEvent e) {
                updateScale();
            }

            @Override
            public void changedUpdate(DocumentEvent e) {
                updateScale();
            }
        };
        ipPatternField.getDocument().addDocumentListener(scaleListener);
        fileField.getDocument().addDocumentListener(scaleListener);
        listArea.getDocument().addDocumentListener(scaleListener);
        updateScale();

        netSpinner.addChangeListener(e -> updateThreadScale());
        updateThreadScale();

        root.add(settings, BorderLayout.NORTH);

        // ---- Log (CENTER - main area) ----
        JPanel logPanel = new RoundedPanel(14, BG_PANEL);
        logPanel.setLayout(new BorderLayout(0, 8));
        logPanel.setBorder(new EmptyBorder(14, 14, 14, 14));

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
        logPane.setBackground(BG_LOG);
        logPane.setFont(FONT_MONO);
        logPane.setCaretColor(TEXT_MUTED);
        logPane.setFocusable(true);
        logPane.setBorder(new EmptyBorder(8, 10, 8, 10));

        JScrollPane scroll = new JScrollPane(logPane);
        scroll.setBorder(BorderFactory.createLineBorder(BORDER, 1, true));
        scroll.getViewport().setBackground(BG_LOG);
        scroll.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED);
        scroll.getVerticalScrollBar().setUnitIncrement(16);
        logPanel.add(scroll, BorderLayout.CENTER);

        root.add(logPanel, BorderLayout.CENTER);

        // ---- Bottom: buttons + status ----
        JPanel bottom = new JPanel(new BorderLayout(0, 8));
        bottom.setOpaque(false);

        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 2));
        buttons.setOpaque(false);

        startButton = new RoundedButton("\u25B6  Start", GREEN_DARK, GREEN);
        startButton.setHoverBg(new Color(52, 168, 90));
        startButton.addActionListener(e -> startScan());

        stopButton = new RoundedButton("\u25A0  Stop", RED_DARK, RED);
        stopButton.setEnabled(false);
        stopButton.addActionListener(e -> stopScan());

        exportButton = new RoundedButton("\uD83D\uDCC4  Export", ACCENT_DARK, ACCENT);
        exportButton.setEnabled(false);
        exportButton.addActionListener(e -> exportResults());

        clearButton = new RoundedButton("Clear log", new Color(58, 61, 82), new Color(78, 82, 110));
        clearButton.setHoverBg(new Color(78, 82, 110));
        clearButton.setForeground(TEXT_MAIN);
        clearButton.addActionListener(e -> {
            clearLog();
            openResults.clear();
            mcResults.clear();
            openCount = 0;
            closedCount = 0;
            scannedNow = 0;
            externalCount = 0;
            updateStats();
            setStatus("Log cleared");
        });

        buttons.add(startButton);
        buttons.add(stopButton);
        buttons.add(exportButton);
        buttons.add(clearButton);
        bottom.add(buttons, BorderLayout.NORTH);

        // Real-time system monitor: CPU, RAM, incoming/outgoing traffic
        JPanel monitorPanel = new RoundedPanel(12, BG_PANEL_2);
        monitorPanel.setLayout(new FlowLayout(FlowLayout.LEFT, 20, 6));
        monitorPanel.setBorder(new EmptyBorder(6, 12, 6, 12));
        cpuLabel = makeMonitorStat("CPU", "--");
        ramLabel = makeMonitorStat("RAM", "--");
        inLabel = makeMonitorStat("IN", "--");
        outLabel = makeMonitorStat("OUT", "--");
        monitorPanel.add(cpuLabel);
        monitorPanel.add(ramLabel);
        monitorPanel.add(inLabel);
        monitorPanel.add(outLabel);
        bottom.add(monitorPanel, BorderLayout.CENTER);

        JPanel statusBar = new RoundedPanel(12, BG_PANEL_2);
        statusBar.setLayout(new BorderLayout(10, 0));
        statusBar.setBorder(new EmptyBorder(8, 12, 8, 12));
        statusLabel = new JLabel("Ready. Enter an IP syntax (regex) and port, then press Start.");
        statusLabel.setFont(FONT_LABEL);
        statusLabel.setForeground(TEXT_MUTED);
        progressBar = new ScanProgressBar();
        progressBar.setPreferredSize(new Dimension(250, 54));
        progressBar.setToolTipText("Scan progress: yellow fill = completed targets");
        statusBar.add(statusLabel, BorderLayout.CENTER);
        statusBar.add(progressBar, BorderLayout.EAST);
        bottom.add(statusBar, BorderLayout.SOUTH);

        root.add(bottom, BorderLayout.SOUTH);

        getContentPane().setLayout(new BorderLayout());
        getContentPane().add(root, BorderLayout.CENTER);
    }

    // ================= UI HELPERS =================

    private JLabel makeLabel(String text) {
        JLabel l = new JLabel(text);
        l.setFont(FONT_LABEL);
        l.setForeground(TEXT_MUTED);
        return l;
    }

    private JLabel makeStat(String text, Color color) {
        JLabel l = new JLabel(text);
        l.setFont(new Font("Segoe UI", Font.BOLD, 13));
        l.setForeground(color);
        return l;
    }

    private JTextField makeField(String initial) {
        return makeField(initial, 0);
    }

    private JTextField makeField(String initial, int columns) {
        JTextField f = new JTextField(initial);
        if (columns > 0) {
            f.setColumns(columns);
        }
        f.setBackground(BG_FIELD);
        f.setForeground(TEXT_MAIN);
        f.setCaretColor(TEXT_MAIN);
        f.setFont(FONT_BODY);
        f.setBorder(BorderFactory.createCompoundBorder(
                BorderFactory.createLineBorder(BORDER, 1, true),
                new EmptyBorder(8, 10, 8, 10)));
        return f;
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

    /**
     * Appends a colored line to the log. The log is NEVER auto-cleared:
     * only the "Clear log" button wipes it.
     */
    private void logArea(String message) {
        SwingUtilities.invokeLater(() -> {
            try {
                String ts = "[" + TIME_FMT.format(new Date()) + "]  ";
                Style tsStyle = logDoc.addStyle("ts", null);
                StyleConstants.setForeground(tsStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), ts, tsStyle);

                Style msgStyle = logDoc.addStyle("msg", null);
                StyleConstants.setForeground(msgStyle, TEXT_MAIN);
                logDoc.insertString(logDoc.getLength(), message + "\n", msgStyle);

                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    /**
     * Logs an action/info line (SCANNING STARTED/FINISHED, stop, export, etc.)
     * only if "Log actions" is enabled in Log Settings.
     */
    private void logAction(String message) {
        if (logActions) logArea(message);
    }

    /** Opens the Log Settings dialog (gear button next to the log). */
    private void openLogSettings() {
        LogSettingsDialog d = new LogSettingsDialog(this);
        d.setLocationRelativeTo(this);
        d.setVisible(true);
    }

    /** Opens the IP parsing settings dialog (gear button next to the Syntax field). */
    private void openIpSettings() {
        IpSettingsDialog d = new IpSettingsDialog(this);
        d.setLocationRelativeTo(this);
        d.setVisible(true);
    }

    // ================= MC-PROBE LOG FILTER =================

    /**
     * Returns true if a Minecraft probe result passes all enabled MC-probe
     * log filters. Called only for successful probes.
     */
    private boolean mcFilterPasses(McProbe.Result probe) {
        if (mcFilterOnline) {
            int[] range = parseNumRange(mcFilterOnlineVal);
            if (range != null && !numInRange(probe.online, mcFilterOnlineOp, range)) return false;
        }
        if (mcFilterVersion && !mcFilterVersionVal.trim().isEmpty()) {
            if (!versionMatches(probe.version, mcFilterVersionOp, mcFilterVersionVal)) return false;
        }
        if (mcFilterBrand && !mcFilterBrandVal.trim().isEmpty()) {
            if (!regexFind(probe.brand, mcFilterBrandVal)) return false;
        }
        if (mcFilterMotd && !mcFilterMotdVal.trim().isEmpty()) {
            if (!regexFind(probe.motd, mcFilterMotdVal)) return false;
        }
        if (mcFilterPlayers && !mcFilterPlayersVal.trim().isEmpty()) {
            boolean any = false;
            if (probe.players != null) {
                for (String name : probe.players) {
                    if (regexFind(name, mcFilterPlayersVal)) {
                        any = true;
                        break;
                    }
                }
            }
            if (!any) return false;
        }
        return true;
    }

    /** Parses "5" or "10-30" into {lo, hi}; null if invalid. */
    private static int[] parseNumRange(String s) {
        if (s == null) return null;
        String t = s.trim();
        if (t.isEmpty()) return null;
        if (t.contains("-")) {
            String[] p = t.split("-");
            if (p.length != 2) return null;
            try {
                int lo = Integer.parseInt(p[0].trim());
                int hi = Integer.parseInt(p[1].trim());
                return new int[]{Math.min(lo, hi), Math.max(lo, hi)};
            } catch (NumberFormatException e) {
                return null;
            }
        }
        try {
            int v = Integer.parseInt(t);
            return new int[]{v, v};
        } catch (NumberFormatException e) {
            return null;
        }
    }

    /** Applies the operator: is / above / below / in-range / out-of-range against {lo, hi}. */
    private static boolean numInRange(int value, String op, int[] range) {
        switch (op) {
            case "is": return value == range[0];
            case "above": return value > range[1];
            case "below": return value < range[0];
            case "in-range": return value >= range[0] && value <= range[1];
            case "out-of-range": return value < range[0] || value > range[1];
            default: return true;
        }
    }

    /** Compares two MC version strings numerically, e.g. "1.21.1" vs "1.21.4". */
    private static int compareVersions(String a, String b) {
        int[] pa = versionParts(a);
        int[] pb = versionParts(b);
        int n = Math.max(pa.length, pb.length);
        for (int i = 0; i < n; i++) {
            int x = i < pa.length ? pa[i] : 0;
            int y = i < pb.length ? pb[i] : 0;
            if (x != y) return Integer.compare(x, y);
        }
        return 0;
    }

    /** Extracts numeric version parts from e.g. "1.21.1-SNAPSHOT" -> {1,21,1}. */
    private static int[] versionParts(String v) {
        if (v == null) return new int[0];
        StringBuilder digits = new StringBuilder();
        for (char c : v.trim().toCharArray()) {
            if (Character.isDigit(c) || c == '.') digits.append(c);
            else if (c == '-' || c == '+') digits.append('.');
        }
        String[] parts = digits.toString().split("\\.");
        java.util.List<Integer> list = new ArrayList<>();
        for (String p : parts) {
            if (!p.isEmpty()) {
                try {
                    list.add(Integer.parseInt(p));
                } catch (NumberFormatException ignored) {
                }
            }
        }
        int[] res = new int[list.size()];
        for (int i = 0; i < res.length; i++) res[i] = list.get(i);
        return res;
    }

    /** Version operator check: is / above / below / in-range / out-of-range ("1.21.1-1.21.4"). */
    private static boolean versionMatches(String version, String op, String spec) {
        String s = spec.trim();
        if ("in-range".equals(op) || "out-of-range".equals(op)) {
            String[] p = s.split("-");
            if (p.length == 2) {
                int c1 = compareVersions(version, p[0].trim());
                int c2 = compareVersions(version, p[1].trim());
                boolean inside = c1 >= 0 && c2 <= 0;
                return "in-range".equals(op) ? inside : !inside;
            }
            if (p.length == 1) {
                // single value: out-of-range = any version except this one
                return "out-of-range".equals(op) && compareVersions(version, s) != 0;
            }
            // malformed multi-dash spec: filter disabled (never discard results)
            return true;
        }
        int c = compareVersions(version, s);
        switch (op) {
            case "is": return c == 0;
            case "above": return c > 0;
            case "below": return c < 0;
            default: return true;
        }
    }

    /**
     * True if the regex is found anywhere in text. An INVALID regex is treated
     * as "filter disabled" (returns true) so a typo never silently discards
     * scan results - consistent with invalid numeric filter values.
     */
    private static boolean regexFind(String text, String regex) {
        if (text == null || regex == null || regex.trim().isEmpty()) return false;
        try {
            return java.util.regex.Pattern.compile(regex).matcher(text).find();
        } catch (Exception e) {
            return true; // invalid regex: don't filter
        }
    }

    /** Clears the log entirely (only used by the "Clear log" button). */
    private void clearLog() {
        SwingUtilities.invokeLater(() -> {
            try {
                logDoc.remove(0, logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    private boolean isMcMode() {
        return modeCombo != null && ((String) modeCombo.getSelectedItem()).contains("Minecraft");
    }

    private void styleCombo(JComboBox<String> combo) {
        // Custom Basic L&F: the Windows L&F paints the combo button white, making
        // the selection invisible on the dark theme. Basic respects the component
        // background, so the field stays dark with visible white text.
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
                // white text on gray backgrounds, never white-on-white
                l.setOpaque(true);
                if (isSelected) {
                    l.setBackground(ACCENT_DARK);
                    l.setForeground(Color.WHITE);
                } else {
                    l.setBackground(BG_PANEL_2);
                    l.setForeground(TEXT_MAIN);
                }
                l.setFont(FONT_BODY);
                l.setBorder(new EmptyBorder(4, 10, 4, 10));
                return l;
            }
        });
    }

    /** Basic ComboBox UI with a dark arrow button (fixes white-on-white). */
    private static class DarkComboBoxUI extends BasicComboBoxUI {
        @Override
        protected JButton createArrowButton() {
            JButton b = new BasicArrowButton(BasicArrowButton.SOUTH,
                    BG_FIELD, BORDER, TEXT_MAIN, ACCENT);
            b.setFocusable(false);
            return b;
        }
    }

    /** Live-updates the IP-count scale when the Syntax field changes. */
    private void updateScale() {
        if ("File".equals(syntaxMode)) {
            String path = fileField.getText().trim();
            try {
                if (path.isEmpty() || !Files.exists(Paths.get(path))) {
                    scalePanel.setState(false, 0);
                    return;
                }
            } catch (Exception ex) {
                // InvalidPathException while typing: no valid file yet
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

    /**
     * Returns the raw pattern lines according to the active input mode:
     * Single - one line, List - one per line, File - lines read from file.
     * Blank lines are skipped.
     */
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
                    // IOException or InvalidPathException: treat as no valid file
                }
            }
        } else {
            String t = ipPatternField.getText().trim();
            if (!t.isEmpty()) lines.add(t);
        }
        return lines;
    }

    /**
     * Converts raw pattern lines through {@link SyntaxConv} according to the
     * active type (ip / wildcard / regex) and CIDR setting. Returns null if
     * ANY non-blank line is invalid for the current type.
     */
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

    /** Applies the active input mode to the Syntax row (only one widget visible). */
    private void applySyntaxMode() {
        ipPatternField.setVisible("Single".equals(syntaxMode));
        listScroll.setVisible("List".equals(syntaxMode));
        fileFieldScroll.setVisible("File".equals(syntaxMode));
        browseButton.setVisible("File".equals(syntaxMode));
        updateSyntaxTooltip();
        updateScale();
    }

    /** Updates the Syntax field tooltip to match the active type. */
    private void updateSyntaxTooltip() {
        String cidrNote = useCidr ? "\nCIDR blocks are ON - e.g. 95.31.0.0/16 or 95.31.***.*/8" : "";
        switch (syntaxType) {
            case "ip":
                ipPatternField.setToolTipText("Type: ip - full IP address.\nExample: 95.31.158.9" + cidrNote);
                break;
            case "wildcard":
                ipPatternField.setToolTipText("Type: wildcard - * means any number.\nExample: 95.31.***.*  (* = any octet value 0-255)" + cidrNote);
                break;
            default:
                ipPatternField.setToolTipText("Type: regex - Java regex for IPv4 addresses.\n"
                        + "Examples: ^95\\.31\\.\\d{1,3}\\.\\d$  |  95\\.31\\.0\\.0/16  |  10.0.0.0/8" + cidrNote);
        }
    }

    /** Opens a file chooser and puts the selected path into the File-mode field. */
    private void choosePatternFile() {
        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Select patterns file (one regex / CIDR per line)");
        chooser.setCurrentDirectory(new File("."));
        if (chooser.showOpenDialog(this) == JFileChooser.APPROVE_OPTION) {
            fileField.setText(chooser.getSelectedFile().getAbsolutePath());
            updateScale();
        }
    }

    /** Live-updates the thread scale when the network threads spinner changes. */
    private void updateThreadScale() {
        int threads = (Integer) netSpinner.getValue();
        threadScale.setValue(threads);
    }

    /** Validates a port spec: 1-65535, single port or A-B range. Returns an error or null. */
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

    private JLabel makeMonitorStat(String name, String value) {
        JLabel l = new JLabel(name + ": " + value);
        l.setFont(new Font("Segoe UI", Font.BOLD, 12));
        l.setForeground(TEXT_MAIN);
        l.setToolTipText(name + " usage of this Java process");
        return l;
    }

    private static String formatRate(long bytesPerSec) {
        if (bytesPerSec >= 1_000_000L) {
            return String.format(Locale.US, "%.1f MB/s", bytesPerSec / 1_000_000.0);
        }
        if (bytesPerSec >= 1_000L) {
            return String.format(Locale.US, "%.1f KB/s", bytesPerSec / 1_000.0);
        }
        return bytesPerSec + " B/s";
    }

    private static String formatBytesTotal(long bytes) {
        if (bytes >= 1_000_000L) {
            return String.format(Locale.US, "%.1f MB", bytes / 1_000_000.0);
        }
        if (bytes >= 1_000L) {
            return String.format(Locale.US, "%.1f KB", bytes / 1_000.0);
        }
        return bytes + " B";
    }

    private static String fmtNum(long n) {
        return String.format(Locale.US, "%,d", n);
    }

    /** Formats an ETA in milliseconds as "d hh:mm:ss" or "hh:mm:ss". */
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

    // Smooth scale gradient: white -> yellow -> orange -> red -> burgundy
    private static final int[][] GRADIENT = {
            {255, 255, 255}, {250, 220, 90}, {255, 160, 60}, {255, 90, 90}, {140, 20, 40}
    };

    private static Color gradientColor(double t) {
        double x = Math.max(0.0, Math.min(1.0, t)) * (GRADIENT.length - 1);
        int i = (int) x;
        if (i >= GRADIENT.length - 1) {
            int[] c = GRADIENT[GRADIENT.length - 1];
            return new Color(c[0], c[1], c[2]);
        }
        double f = x - i;
        int r = (int) (GRADIENT[i][0] + (GRADIENT[i + 1][0] - GRADIENT[i][0]) * f);
        int g = (int) (GRADIENT[i][1] + (GRADIENT[i + 1][1] - GRADIENT[i][1]) * f);
        int b = (int) (GRADIENT[i][2] + (GRADIENT[i + 1][2] - GRADIENT[i][2]) * f);
        return new Color(r, g, b);
    }

    /** Position 0..1 of an IP count on the log scale. */
    private static double ipPosition(long count) {
        double logC = Math.log10(Math.max(count, 1));
        return Math.min(1.0, Math.max(0.0, logC / 12.0));
    }

    /** Updates CPU / RAM / traffic labels (called once per second). */
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
            // never let a monitor error kill the timer tick
        }
    }

    private static String formatCount(long n) {
        if (n >= 1_000_000_000L) {
            return String.format(Locale.US, "%.1f B IPs", n / 1_000_000_000.0);
        }
        if (n >= 1_000_000L) {
            return String.format(Locale.US, "%.1f M IPs", n / 1_000_000.0);
        }
        return String.format(Locale.US, "%,d IPs", n);
    }

    /**
     * Appends a log line where the message text is colored and the IP:port highlighted.
     */
    private void logResult(String ip, int port, String label, Color color, long timeMs) {
        SwingUtilities.invokeLater(() -> {
            try {
                String ts = "[" + TIME_FMT.format(new Date()) + "]  ";
                Style tsStyle = logDoc.addStyle("ts", null);
                StyleConstants.setForeground(tsStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), ts, tsStyle);

                // colored status tag
                Style tagStyle = logDoc.addStyle("tag", null);
                StyleConstants.setForeground(tagStyle, color);
                StyleConstants.setBold(tagStyle, true);
                logDoc.insertString(logDoc.getLength(), label + "  ", tagStyle);

                // ip:port in bright color
                Style addrStyle = logDoc.addStyle("addr", null);
                StyleConstants.setForeground(addrStyle, color);
                StyleConstants.setBold(addrStyle, true);
                logDoc.insertString(logDoc.getLength(), ip + ":" + port, addrStyle);

                // response time in muted
                Style msStyle = logDoc.addStyle("ms", null);
                StyleConstants.setForeground(msStyle, TEXT_MUTED);
                logDoc.insertString(logDoc.getLength(), "   (" + timeMs + " ms)\n", msStyle);

                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    private void updateStats() {
        SwingUtilities.invokeLater(() -> {
            totalLabel.setText("Total: " + totalTargets);
            openLabel.setText("Open: " + openCount);
            externalLabel.setText("External: " + externalCount);
            closedLabel.setText("Closed: " + closedCount);
        });
    }

    /**
     * Status 2: external availability line (port forwarding / public IP).
     * Shown under each result when the "Status 2" checkbox is enabled.
     */
    private void logExternal(String ip, int port, PortScanner.Result result, long timeMs) {
        boolean open = result == PortScanner.Result.OPEN;
        boolean timeout = result == PortScanner.Result.TIMEOUT;
        boolean publicIp = IpUtils.isPublic(ip);
        boolean sameLan = IpUtils.isSameLan(ip);
        String verdict = IpUtils.externalStatus(ip, open, timeout);
        Color color;
        if (sameLan || !publicIp) {
            color = TEXT_MUTED;
        } else if (open) {
            color = GREEN;
        } else if (timeout) {
            color = YELLOW;
        } else {
            color = RED;
        }
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
                StyleConstants.setForeground(verdictStyle, color);
                logDoc.insertString(logDoc.getLength(), "  " + ip + ":" + port + " — " + verdict + "   (" + timeMs + " ms)\n", verdictStyle);

                logPane.setCaretPosition(logDoc.getLength());
            } catch (BadLocationException ignored) {
            }
        });
    }

    /** Minecraft probe result line: server found with version/players/MOTD. */
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

                // details: version, players, motd
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
    }

    private void setStatus(String text) {
        statusLabel.setText(text);
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
        openCount = 0;
        closedCount = 0;
        scannedNow = 0;
        externalCount = 0;
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
        String modeLabel = syntaxMode.toLowerCase();
        logAction("Mode: " + (isMcMode() ? "Minecraft (mcprobe)" : "Telnet (TCP)")
                + "   |   Syntax: type=" + syntaxType + ", input=" + modeLabel
                + ", CIDR=" + (useCidr ? "on" : "off")
                + "   |   " + patternLines.size() + " pattern(s)   (" + totalIps + " addresses)");
        logAction("Port: " + portDesc + "   (targets: " + totalTargets + ")");
        logAction("Timeout: " + timeout + " ms,  CPU threads: " + parseThreads + " parse / " + genThreads + " gen,  network: " + netThreads);
        if (externalCheck.isSelected()) {
            logAction("Status 2 enabled: public IP + open port = reachable from outside");
        }
        updateStats();

        saveSettings();

        startButton.setEnabled(false);
        stopButton.setEnabled(true);
        exportButton.setEnabled(false);

        if (isMcMode()) {
            startMcScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads);
        } else {
            startTelnetScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads);
        }
    }

    /**
     * Telnet mode: plain TCP port check.
     * Iteration order: all ports of one IP first, then the next IP.
     */
    private void startTelnetScan(List<List<List<Integer>>> blocks, int startPort, int endPort, int timeout,
                                 int parseThreads, int genThreads, int netThreads) {
        scanner = new PortScanner();
        scanner.startScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads, new PortScanner.ScanCallback() {
            @Override
            public void onResult(String ip, int port, PortScanner.Result result, long timeMs) {
                if (result == PortScanner.Result.OPEN) {
                    openCount++;
                    openResults.add(ip + ":" + port);
                    if (logOpen) logResult(ip, port, "\u2705 OPEN", GREEN, timeMs);
                    if (externalCheck.isSelected() && IpUtils.isPublic(ip) && !IpUtils.isSameLan(ip)) {
                        externalCount++;
                    }
                } else {
                    if (result == PortScanner.Result.CLOSED) {
                        closedCount++;
                        if (logClosed) logResult(ip, port, "\u274C CLOSED", RED, timeMs);
                    } else if (result == PortScanner.Result.TIMEOUT) {
                        if (logTimeout) logResult(ip, port, "\u23F3 TIMEOUT", YELLOW, timeMs);
                    } else {
                        if (logError) logResult(ip, port, "\u2753 ERROR", GRAY, timeMs);
                    }
                }
                if (externalCheck.isSelected()) {
                    logExternal(ip, port, result, timeMs);
                }
            }

            @Override
            public void onProgress(long scanned, long total) {
                scannedNow = (int) Math.min(scanned, Integer.MAX_VALUE);
                long last = lastProgressPosted;
                if (scanned != total && scanned - last < Math.max(1, total / 500)) {
                    return; // throttled: keep the UI smooth on huge scans
                }
                lastProgressPosted = scanned;
                long left = total - scanned;
                double pct = total == 0 ? 0 : scanned * 100.0 / total;
                long elapsedMs = (System.nanoTime() - scanStartNanos) / 1_000_000L;
                long etaMs = (scanned > 0 && elapsedMs > 0 && left > 0)
                        ? (long) (left * (double) elapsedMs / scanned) : 0;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setProgress(pct);
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
                    String ext = externalCheck.isSelected() ? "  |  External: " + externalCount : "";
                    setStatus("Done. Open ports: " + openCount + ext);
                    statusLabel.setForeground(TEXT_MUTED);
                    logAction("");
                    logAction("═══════════════════ SCANNING FINISHED ═══════════════════");
                    logAction("Open ports: " + openCount + "  |  Closed: " + closedCount + ext);
                });
            }
        });
    }

    /**
     * Minecraft mode: probe servers with the Server List Ping protocol
     * (version, MOTD, players online/max, latency).
     * Iteration order: all ports of one IP first, then the next IP.
     */
    private void startMcScan(List<List<List<Integer>>> blocks, int startPort, int endPort, int timeout,
                             int parseThreads, int genThreads, int netThreads) {
        mcScanner = new McProbeScanner();
        mcScanner.startScan(blocks, startPort, endPort, timeout, parseThreads, genThreads, netThreads, new McProbeScanner.ScanCallback() {
            @Override
            public void onResult(String ip, int port, McProbe.Result probe) {
                if (probe.success) {
                    if (!mcFilterPasses(probe)) {
                        return; // filtered out by MC-probe log filter: not logged, not counted
                    }
                    openCount++;
                    String key = ip + ":" + port;
                    openResults.add(key);
                    mcResults.put(key, probe);
                    logMcResult(ip, port, probe);
                    if (externalCheck.isSelected() && IpUtils.isPublic(ip) && !IpUtils.isSameLan(ip)) {
                        externalCount++;
                    }
                } else {
                    closedCount++;
                    if (logClosed) logResult(ip, port, "\u274C CLOSED", RED, probe.latencyMs);
                }
                if (externalCheck.isSelected()) {
                    logExternal(ip, port, probe.success ? PortScanner.Result.OPEN : PortScanner.Result.CLOSED, probe.latencyMs);
                }
            }

            @Override
            public void onProgress(long scanned, long total) {
                scannedNow = (int) Math.min(scanned, Integer.MAX_VALUE);
                long last = lastProgressPosted;
                if (scanned != total && scanned - last < Math.max(1, total / 500)) {
                    return; // throttled: keep the UI smooth on huge scans
                }
                lastProgressPosted = scanned;
                long left = total - scanned;
                double pct = total == 0 ? 0 : scanned * 100.0 / total;
                long elapsedMs = (System.nanoTime() - scanStartNanos) / 1_000_000L;
                long etaMs = (scanned > 0 && elapsedMs > 0 && left > 0)
                        ? (long) (left * (double) elapsedMs / scanned) : 0;
                SwingUtilities.invokeLater(() -> {
                    progressBar.setProgress(pct);
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
                    String ext = externalCheck.isSelected() ? "  |  External: " + externalCount : "";
                    setStatus("Done. MC servers found: " + openCount + ext);
                    statusLabel.setForeground(TEXT_MUTED);
                    logAction("");
                    logAction("═══════════════════ SCANNING FINISHED ═══════════════════");
                    logAction("MC servers found: " + openCount + "  |  No response: " + closedCount + ext);
                });
            }
        });
    }

    private void stopScan() {
        if (scanner != null) scanner.stop();
        if (mcScanner != null) mcScanner.stop();
        logAction("--- Scan stopped by user ---");
        startButton.setEnabled(true);
        stopButton.setEnabled(false);
        exportButton.setEnabled(true);
        setStatus("Stopped. Found: " + openCount);
        statusLabel.setForeground(TEXT_MUTED);
    }

    private void exportResults() {
        if (openResults.isEmpty()) {
            JOptionPane.showMessageDialog(this, "No results to export.");
            return;
        }

        JFileChooser chooser = new JFileChooser();
        chooser.setDialogTitle("Save results");
        chooser.setSelectedFile(new File("results_" + TIME_FMT.format(new Date()).replace(":", "-") + ".txt"));
        chooser.setCurrentDirectory(new File("."));

        if (chooser.showSaveDialog(this) == JFileChooser.APPROVE_OPTION) {
            File file = chooser.getSelectedFile();
            if (!file.getName().toLowerCase().endsWith(".txt")) {
                file = new File(file.getParentFile(), file.getName() + ".txt");
            }
            try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
                writer.write("IP Parser - scan results");
                writer.newLine();
                writer.write("Time: " + new SimpleDateFormat("yyyy-MM-dd HH:mm:ss").format(new Date()));
                writer.newLine();
                writer.write("Mode: " + (isMcMode() ? "Minecraft (mcprobe)" : "Telnet (TCP)"));
                writer.newLine();
                writer.write("Syntax (type=" + syntaxType + ", input=" + syntaxMode.toLowerCase()
                        + ", CIDR=" + (useCidr ? "on" : "off") + "): " + patternLinesForExport());
                writer.newLine();
                writer.write("Port: " + portField.getText().trim());
                writer.newLine();
                writer.write("Open ports: " + openResults.size());
                writer.newLine();
                if (externalCheck.isSelected()) {
                    writer.write("Reachable from outside (public IP): " + externalCount);
                    writer.newLine();
                }
                writer.write("------------------------------------------");
                writer.newLine();
                for (String res : openResults) {
                    String line = res;
                    if (isMcMode()) {
                        McProbe.Result p = mcResults.get(res);
                        if (p != null) {
                            String version = p.version.isEmpty() ? "?" : p.version;
                            line = res + "  |  version: " + version
                                    + (p.brand.isEmpty() ? "" : "  |  brand: " + p.brand)
                                    + "  |  players: " + p.online + "/" + p.max
                                    + (p.motd.isEmpty() ? "" : "  |  " + p.motd);
                        }
                    }
                    if (externalCheck.isSelected()) {
                        String ip = res.contains(":") ? res.substring(0, res.lastIndexOf(':')) : res;
                        line = line + "  —  " + IpUtils.externalStatus(ip, true, false);
                    }
                    writer.write(line);
                    writer.newLine();
                }
                logAction("\uD83D\uDCC4 Exported: " + file.getAbsolutePath());
                setStatus("Results saved: " + file.getName());
            } catch (IOException ex) {
                JOptionPane.showMessageDialog(this, "Save error: " + ex.getMessage());
            }
        }
    }

    /**
     * Human-readable description of the active syntax for the export header.
     * List mode joins lines with " ; ", File mode shows the file path.
     */
    private String patternLinesForExport() {
        if ("File".equals(syntaxMode)) {
            return fileField.getText().trim();
        }
        List<String> lines = currentPatternLines();
        return lines.isEmpty() ? "" : String.join(" ; ", lines);
    }

    private void loadSettings() {
        try {
            if (!Files.exists(Paths.get("settings.txt"))) return;
            List<String> lines = Files.readAllLines(Paths.get("settings.txt"));
            if (lines.size() >= 2) {
                // line 0 may be a single pattern, or list/file content (see saveSettings)
                String p0 = lines.get(0);
                if (lines.size() >= 9 && "list".equals(lines.get(8))) {
                    listArea.setText(p0.replace("\u0001", "\n"));
                } else if (lines.size() >= 9 && "file".equals(lines.get(8))) {
                    fileField.setText(p0);
                } else {
                    ipPatternField.setText(p0);
                }
                portField.setText(lines.get(1));
            }
            if (lines.size() >= 3) timeoutField.setText(lines.get(2));
            if (lines.size() >= 4) parseSpinner.setValue(clampInt(lines.get(3), parseSpinner));
            if (lines.size() >= 5) genSpinner.setValue(clampInt(lines.get(4), genSpinner));
            if (lines.size() >= 6) netSpinner.setValue(clampInt(lines.get(5), netSpinner));
            if (lines.size() >= 7) externalCheck.setSelected(lines.get(6).equals("1"));
            if (lines.size() >= 8) modeCombo.setSelectedIndex(clampInt(lines.get(7), 0, modeCombo.getItemCount() - 1));
            if (lines.size() >= 9) {
                String mode = lines.get(8);
                if ("list".equals(mode)) syntaxMode = "List";
                else if ("file".equals(mode)) syntaxMode = "File";
                else syntaxMode = "Single";
            }
            if (lines.size() >= 14) {
                logOpen = lines.get(9).equals("1");
                logClosed = lines.get(10).equals("1");
                logTimeout = lines.get(11).equals("1");
                logError = lines.get(12).equals("1");
                logActions = lines.get(13).equals("1");
            }
            if (lines.size() >= 17) {
                mcFilterOnline = lines.get(14).equals("1");
                mcFilterOnlineOp = lines.get(15);
                mcFilterOnlineVal = lines.get(16);
            }
            if (lines.size() >= 20) {
                mcFilterVersion = lines.get(17).equals("1");
                mcFilterVersionOp = lines.get(18);
                mcFilterVersionVal = lines.get(19);
            }
            if (lines.size() >= 22) {
                mcFilterBrand = lines.get(20).equals("1");
                mcFilterBrandVal = lines.get(21);
            }
            if (lines.size() >= 24) {
                mcFilterMotd = lines.get(22).equals("1");
                mcFilterMotdVal = lines.get(23);
            }
            if (lines.size() >= 28) {
                syntaxType = lines.get(26);
                useCidr = lines.get(27).equals("1");
            }
            applySyntaxMode();
        } catch (IOException | NumberFormatException ignored) {
        }
    }

    /** Parses a setting int and clamps it into the spinner's range (old files may be out of bounds). */
    private static int clampInt(String text, JSpinner spinner) {
        int v = Integer.parseInt(text);
        SpinnerNumberModel m = (SpinnerNumberModel) spinner.getModel();
        return Math.max(((Number) m.getMinimum()).intValue(),
                Math.min(((Number) m.getMaximum()).intValue(), v));
    }

    /** Parses a setting int and clamps it into [min, max]. */
    private static int clampInt(String text, int min, int max) {
        int v = Integer.parseInt(text);
        return Math.max(min, Math.min(max, v));
    }

    private void saveSettings() {
        try {
            String mode = syntaxMode;
            String p0;
            if ("List".equals(mode)) {
                // newlines are encoded as \u0001 so the settings file stays line-based
                p0 = listArea.getText().replace("\n", "\u0001");
            } else if ("File".equals(mode)) {
                p0 = fileField.getText().trim();
            } else {
                p0 = ipPatternField.getText().trim();
            }
            List<String> lines = List.of(
                    p0,
                    portField.getText().trim(),
                    timeoutField.getText().trim(),
                    String.valueOf(parseSpinner.getValue()),
                    String.valueOf(genSpinner.getValue()),
                    String.valueOf(netSpinner.getValue()),
                    externalCheck.isSelected() ? "1" : "0",
                    String.valueOf(modeCombo.getSelectedIndex()),
                    mode.toLowerCase(),
                    logOpen ? "1" : "0",
                    logClosed ? "1" : "0",
                    logTimeout ? "1" : "0",
                    logError ? "1" : "0",
                    logActions ? "1" : "0",
                    mcFilterOnline ? "1" : "0",
                    mcFilterOnlineOp,
                    mcFilterOnlineVal,
                    mcFilterVersion ? "1" : "0",
                    mcFilterVersionOp,
                    mcFilterVersionVal,
                    mcFilterBrand ? "1" : "0",
                    mcFilterBrandVal,
                    mcFilterMotd ? "1" : "0",
                    mcFilterMotdVal,
                    mcFilterPlayers ? "1" : "0",
                    mcFilterPlayersVal,
                    syntaxType,
                    useCidr ? "1" : "0");
            Files.write(Paths.get("settings.txt"), lines);
        } catch (IOException ignored) {
        }
    }

    // ================= LOG SETTINGS DIALOG =================

    /**
     * Modal dialog with log output settings and MC-probe log filters.
     * Opened via the gear button next to the log window.
     */
    private class LogSettingsDialog extends JDialog {
        private final JCheckBox openCb, closedCb, timeoutCb, errorCb, actionsCb, status2Cb;
        private final JCheckBox fOnline, fVersion, fBrand, fMotd, fPlayers;
        private final JComboBox<String> opOnline, opVersion;
        private final JTextField valOnline, valVersion, valBrand, valMotd, valPlayers;

        LogSettingsDialog(IpParserGUI owner) {
            super(owner, "Log Settings", true);
            setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

            JPanel root = new JPanel(new BorderLayout(12, 12));
            root.setBackground(BG_ROOT);
            root.setBorder(new EmptyBorder(16, 16, 16, 16));

            JPanel cols = new JPanel(new GridLayout(1, 2, 18, 0));
            cols.setOpaque(false);

            // ---- Left: Logs settings ----
            JPanel left = new RoundedPanel(12, BG_PANEL);
            left.setLayout(new GridBagLayout());
            left.setBorder(new EmptyBorder(12, 14, 12, 14));
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(4, 4, 4, 4);
            g.anchor = GridBagConstraints.WEST;
            g.gridx = 0; g.gridy = 0; g.gridwidth = 2;
            left.add(sectionTitle("Logs settings"), g);
            g.gridwidth = 1;
            g.gridy++;
            openCb = logCheckbox("Log available IP/Port connections", logOpen);
            left.add(openCb, g); g.gridy++;
            closedCb = logCheckbox("Log closed IP/Port connections", logClosed);
            left.add(closedCb, g); g.gridy++;
            timeoutCb = logCheckbox("Log timed out IP/Port connections", logTimeout);
            left.add(timeoutCb, g); g.gridy++;
            errorCb = logCheckbox("Log errored IP/Port connections", logError);
            left.add(errorCb, g); g.gridy++;
            actionsCb = logCheckbox("Log actions (e.g. change IP regex)", logActions);
            left.add(actionsCb, g); g.gridy++;
            status2Cb = logCheckbox("Status 2: port reachable from outside (public IP)", externalCheck.isSelected());
            status2Cb.setToolTipText("Show port reachability from outside as a second status.\n"
                    + "Public IP + open port = reachable from outside (port forwarded).\n"
                    + "Works locally, no external services.");
            left.add(status2Cb, g);
            cols.add(left);

            // ---- Right: MC-probe log filter ----
            JPanel right = new RoundedPanel(12, BG_PANEL);
            right.setLayout(new GridBagLayout());
            right.setBorder(new EmptyBorder(12, 14, 12, 14));
            GridBagConstraints gr = new GridBagConstraints();
            gr.insets = new Insets(4, 4, 4, 4);
            gr.anchor = GridBagConstraints.WEST;
            gr.gridx = 0; gr.gridy = 0; gr.gridwidth = 4;
            right.add(sectionTitle("MC-probe log filter"), gr);
            gr.gridwidth = 1;

            gr.gridy++;
            fOnline = logCheckbox("Log if online", mcFilterOnline);
            opOnline = opCombo(mcFilterOnlineOp);
            valOnline = filterField(mcFilterOnlineVal, "value / range, e.g. 5  or  10-30\n(above/below/in-range/out-of-range)");
            addFilterRow(right, gr, fOnline, opOnline, valOnline);

            gr.gridy++;
            fVersion = logCheckbox("Log if version", mcFilterVersion);
            opVersion = opCombo(mcFilterVersionOp);
            valVersion = filterField(mcFilterVersionVal, "value / range, e.g. 1.21.1  or  1.21.1-1.21.4\n(above/below/in-range/out-of-range)");
            addFilterRow(right, gr, fVersion, opVersion, valVersion);

            gr.gridy++;
            fBrand = logCheckbox("Log if brand name contains", mcFilterBrand);
            valBrand = filterField(mcFilterBrandVal, "java regex, e.g. Leaf|Paper  ((?i) for case-insensitive)");
            addFilterRow(right, gr, fBrand, null, valBrand);

            gr.gridy++;
            fMotd = logCheckbox("Log if MOTD contains", mcFilterMotd);
            valMotd = filterField(mcFilterMotdVal, "java regex, e.g. \\bAnarchy\\b");
            addFilterRow(right, gr, fMotd, null, valMotd);

            gr.gridy++;
            fPlayers = logCheckbox("Log if player list contains", mcFilterPlayers);
            valPlayers = filterField(mcFilterPlayersVal, "java regex, e.g. Notch");
            addFilterRow(right, gr, fPlayers, null, valPlayers);

            gr.gridy++;
            JLabel hint = new JLabel("Empty value = filter disabled.\n"
                    + "Operators: is / above / below / in-range.");
            hint.setFont(new Font("Segoe UI", Font.PLAIN, 10));
            hint.setForeground(TEXT_MUTED);
            gr.gridwidth = 4;
            right.add(hint, gr);
            cols.add(right);

            root.add(cols, BorderLayout.CENTER);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
            buttons.setOpaque(false);
            RoundedButton ok = new RoundedButton("Apply", ACCENT_DARK, ACCENT);
            ok.addActionListener(e -> {
                apply();
                dispose();
            });
            RoundedButton cancel = new RoundedButton("Cancel", new Color(58, 61, 82), new Color(78, 82, 110));
            cancel.setForeground(TEXT_MAIN);
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
            l.setFont(new Font("Segoe UI", Font.BOLD, 14));
            l.setForeground(ACCENT);
            return l;
        }

        private JCheckBox logCheckbox(String text, boolean selected) {
            JCheckBox cb = new JCheckBox(text);
            cb.setOpaque(false);
            cb.setForeground(TEXT_MAIN);
            cb.setFont(FONT_LABEL);
            cb.setSelected(selected);
            cb.setIcon(new DarkCheckIcon());
            cb.setFocusPainted(false);
            cb.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            return cb;
        }

        private JComboBox<String> opCombo(String op) {
            JComboBox<String> cb = new JComboBox<>(new String[]{"is", "above", "below", "in-range", "out-of-range"});
            styleCombo(cb);
            cb.setSelectedItem(op);
            cb.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            return cb;
        }

        private JTextField filterField(String value, String tooltip) {
            JTextField f = makeField(value, 14);
            f.setToolTipText(tooltip);
            return f;
        }

        private void addFilterRow(JPanel panel, GridBagConstraints gr,
                                  JCheckBox cb, JComboBox<String> op, JTextField field) {
            panel.add(cb, gr);
            gr.gridx = 1;
            if (op != null) {
                panel.add(op, gr);
                gr.gridx = 2;
            } else {
                gr.gridx = 2;
            }
            panel.add(field, gr);
            gr.gridx = 3;
            panel.add(Box.createHorizontalStrut(8), gr);
            gr.gridx = 0;
            // enable/disable the widgets when the checkbox toggles
            Runnable sync = () -> {
                boolean on = cb.isSelected();
                if (op != null) op.setEnabled(on);
                field.setEnabled(on);
            };
            cb.addItemListener(e -> sync.run());
            sync.run();
        }

        private void apply() {
            logOpen = openCb.isSelected();
            logClosed = closedCb.isSelected();
            logTimeout = timeoutCb.isSelected();
            logError = errorCb.isSelected();
            logActions = actionsCb.isSelected();
            externalCheck.setSelected(status2Cb.isSelected());

            mcFilterOnline = fOnline.isSelected() && !valOnline.getText().trim().isEmpty();
            mcFilterOnlineOp = (String) opOnline.getSelectedItem();
            mcFilterOnlineVal = valOnline.getText().trim();

            mcFilterVersion = fVersion.isSelected() && !valVersion.getText().trim().isEmpty();
            mcFilterVersionOp = (String) opVersion.getSelectedItem();
            mcFilterVersionVal = valVersion.getText().trim();

            mcFilterBrand = fBrand.isSelected() && !valBrand.getText().trim().isEmpty();
            mcFilterBrandVal = valBrand.getText().trim();

            mcFilterMotd = fMotd.isSelected() && !valMotd.getText().trim().isEmpty();
            mcFilterMotdVal = valMotd.getText().trim();

            mcFilterPlayers = fPlayers.isSelected() && !valPlayers.getText().trim().isEmpty();
            mcFilterPlayersVal = valPlayers.getText().trim();

            saveSettings();
        }
    }

    // ================= IP PARSING SETTINGS DIALOG =================

    /**
     * Modal dialog with the IP parsing settings: type (ip / wildcard / regex),
     * input mode (single / list / file) and the CIDR toggle.
     * Opened via the gear button next to the Syntax field.
     */
    private class IpSettingsDialog extends JDialog {
        private final JComboBox<String> typeCombo, modeCombo, cidrCombo;
        private final JLabel hintLabel;

        IpSettingsDialog(IpParserGUI owner) {
            super(owner, "IP parsing settings", true);
            setDefaultCloseOperation(JDialog.DISPOSE_ON_CLOSE);

            JPanel root = new JPanel(new BorderLayout(12, 12));
            root.setBackground(BG_ROOT);
            root.setBorder(new EmptyBorder(16, 16, 16, 16));

            JPanel form = new JPanel(new GridBagLayout());
            form.setOpaque(false);
            GridBagConstraints g = new GridBagConstraints();
            g.insets = new Insets(5, 4, 5, 4);
            g.anchor = GridBagConstraints.WEST;

            g.gridx = 0; g.gridy = 0;
            form.add(makeLabel("Type"), g);
            g.gridx = 1; g.gridwidth = 2; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
            typeCombo = new JComboBox<>(new String[]{"ip", "wildcard", "regex"});
            styleCombo(typeCombo);
            typeCombo.setSelectedItem(syntaxType);
            typeCombo.setToolTipText("How the Syntax field is interpreted:"
                    + "\nip - a full IP, e.g. 95.31.158.9"
                    + "\nwildcard - * means any number, e.g. 95.31.***.*"
                    + "\nregex - a Java regex, e.g. ^95\\.31\\.\\d{1,3}\\.\\d$");
            typeCombo.addActionListener(e -> updateHint());
            form.add(typeCombo, g);
            g.gridwidth = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE;

            g.gridy = 1; g.gridx = 0;
            form.add(makeLabel("Input mode"), g);
            g.gridx = 1; g.gridwidth = 2; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
            modeCombo = new JComboBox<>(new String[]{"Single", "List", "File"});
            styleCombo(modeCombo);
            modeCombo.setSelectedItem(syntaxMode);
            modeCombo.setToolTipText("Single - one pattern\nList - several patterns, one per line\nFile - path to a file with one pattern per line");
            form.add(modeCombo, g);
            g.gridwidth = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE;

            g.gridy = 2; g.gridx = 0;
            form.add(makeLabel("Use CIDR"), g);
            g.gridx = 1; g.gridwidth = 2; g.weightx = 1.0; g.fill = GridBagConstraints.HORIZONTAL;
            cidrCombo = new JComboBox<>(new String[]{"no", "yes"});
            styleCombo(cidrCombo);
            cidrCombo.setSelectedItem(useCidr ? "yes" : "no");
            cidrCombo.setToolTipText("Interpret CIDR blocks: 95.31.0.0/16, 95.31.158.9/24, 95.31.***.*/8");
            cidrCombo.addActionListener(e -> updateHint());
            form.add(cidrCombo, g);
            g.gridwidth = 1; g.weightx = 0; g.fill = GridBagConstraints.NONE;

            g.gridy = 3; g.gridx = 0; g.gridwidth = 3; g.insets = new Insets(10, 4, 0, 4);
            hintLabel = new JLabel();
            hintLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            hintLabel.setForeground(TEXT_MUTED);
            form.add(hintLabel, g);
            updateHint();

            root.add(form, BorderLayout.CENTER);

            JPanel buttons = new JPanel(new FlowLayout(FlowLayout.RIGHT, 10, 0));
            buttons.setOpaque(false);
            RoundedButton apply = new RoundedButton("Apply", ACCENT_DARK, ACCENT);
            apply.addActionListener(e -> {
                syntaxType = (String) typeCombo.getSelectedItem();
                syntaxMode = (String) modeCombo.getSelectedItem();
                useCidr = "yes".equals(cidrCombo.getSelectedItem());
                applySyntaxMode();
                saveSettings();
                dispose();
            });
            RoundedButton cancel = new RoundedButton("Cancel", new Color(58, 61, 82), new Color(78, 82, 110));
            cancel.setForeground(TEXT_MAIN);
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

    // ================= CUSTOM COMPONENTS =================

    /** Rounded panel with solid background. */
    private static class RoundedPanel extends JPanel {
        private final int radius;
        private final Color bg;

        RoundedPanel(int radius, Color bg) {
            this.radius = radius;
            this.bg = bg;
            setOpaque(false);
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(bg);
            g2.fillRoundRect(0, 0, getWidth() - 1, getHeight() - 1, radius, radius);
            g2.dispose();
            super.paintComponent(g);
        }
    }

    /** Dark, rounded, hoverable button. */
    private static class RoundedButton extends JButton {
        private final Color baseBg;
        private final Color pressBg;
        private Color hoverBg;

        RoundedButton(String text, Color base, Color hover) {
            super(text);
            this.baseBg = base;
            this.hoverBg = hover != null ? hover : base.brighter();
            this.pressBg = base.darker();
            setForeground(Color.WHITE);
            setFont(FONT_BTN);
            setFocusPainted(false);
            setContentAreaFilled(false);
            setBorderPainted(false);
            setOpaque(false);
            setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
            setBorder(new EmptyBorder(9, 18, 9, 18));
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

        void setHoverBg(Color c) {
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
                // subtle top highlight
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

    /** Dark custom checkbox icon. */
    private static class DarkCheckIcon implements Icon {
        private final int size = 16;

        @Override
        public void paintIcon(Component c, Graphics g, int x, int y) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            g2.setColor(BG_FIELD);
            g2.fillRoundRect(x, y, size, size, 4, 4);
            g2.setColor(BORDER);
            g2.drawRoundRect(x, y, size, size, 4, 4);
            JCheckBox cb = (JCheckBox) c;
            if (cb.isSelected()) {
                g2.setColor(ACCENT);
                g2.setStroke(new BasicStroke(2.4f, BasicStroke.CAP_ROUND, BasicStroke.JOIN_ROUND));
                g2.drawLine(x + 3, y + 8, x + 6, y + 11);
                g2.drawLine(x + 6, y + 11, x + 13, y + 4);
            }
            g2.dispose();
        }

        @Override
        public int getIconWidth() {
            return size;
        }

        @Override
        public int getIconHeight() {
            return size;
        }
    }

    /** Live IP-count scale: colored gauge + count + description, next to the Syntax field. */
    private class IpScale extends JPanel {
        private final IpGauge gauge = new IpGauge();
        private final JLabel countLabel = new JLabel();
        private final JLabel descLabel = new JLabel();

        IpScale() {
            setOpaque(false);
            setLayout(new BorderLayout(10, 0));

            gauge.setPreferredSize(new Dimension(150, 36));
            gauge.setMinimumSize(new Dimension(120, 36));
            add(gauge, BorderLayout.WEST);

            JPanel text = new JPanel();
            text.setOpaque(false);
            text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
            countLabel.setFont(new Font("Segoe UI", Font.BOLD, 12));
            descLabel.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            descLabel.setForeground(TEXT_MUTED);
            text.add(countLabel);
            text.add(descLabel);
            add(text, BorderLayout.CENTER);

            setState(false, 0);
        }

        void setState(boolean structureOk, long count) {
            boolean valid = structureOk && count > 0;
            gauge.setCount(count, valid);
            if (!structureOk) {
                countLabel.setForeground(RED);
                countLabel.setText("Invalid regex");
                descLabel.setText("4 octets 0-255, dots between");
            } else if (!valid) {
                countLabel.setForeground(GRAY);
                countLabel.setText("No IPs matched");
                descLabel.setText("Nothing matches in the 0-255 range");
            } else {
                Band band = Band.forCount(count);
                countLabel.setForeground(gradientColor(ipPosition(count)));
                countLabel.setText(formatCount(count));
                descLabel.setText(band.desc);
            }
        }
    }

    /** Color/description bands for the IP-count scale. */
    private enum Band {
        NORMAL(new Color(88, 230, 140), "Normal - quick scan"),
        NORMAL_UP(new Color(170, 230, 90), "Normal - a minute or two"),
        ELEVATED(new Color(250, 200, 90), "Elevated - may take several minutes"),
        HIGH(new Color(255, 160, 60), "High - may take tens of minutes"),
        VERY_HIGH(new Color(255, 105, 105), "Very high - may take hours"),
        EXTREME(new Color(210, 70, 60), "Extreme - may take many hours"),
        MASSIVE(new Color(160, 60, 170), "Massive - may take days");

        final Color color;
        final String desc;

        Band(Color color, String desc) {
            this.color = color;
            this.desc = desc;
        }

        static Band forCount(long count) {
            if (count <= 10_000) return NORMAL;
            if (count <= 100_000) return NORMAL_UP;
            if (count <= 1_000_000) return ELEVATED;
            if (count <= 10_000_000) return HIGH;
            if (count <= 100_000_000) return VERY_HIGH;
            if (count <= 1_000_000_000) return EXTREME;
            return MASSIVE;
        }
    }

    /** Horizontal log-scale gauge with colored bands, ticks and a white marker. */
    private static class IpGauge extends JComponent {
        private static final double[] BOUNDS = {0, 4, 5, 6, 7, 8, 9, 12}; // log10 of count limits
        private static final String[] TICKS = {"1", "10k", "1M", "100M", "1B"};
        private static final double[] TICK_LOG = {0, 4, 6, 8, 9};

        private long count = 0;
        private boolean valid = false;

        void setCount(long count, boolean valid) {
            this.count = count;
            this.valid = valid;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth();
            int h = getHeight();
            int left = 8;
            int right = w - 8;
            int barY = h / 2 - 6;
            int barH = 8;
            double span = BOUNDS[BOUNDS.length - 1] - BOUNDS[0];

            if (!valid) {
                g2.setColor(BG_PANEL_2);
                g2.fillRoundRect(left, barY, Math.max(1, right - left), barH, barH, barH);
                g2.setColor(TEXT_MUTED);
                g2.setFont(new Font("Segoe UI", Font.PLAIN, 9));
                g2.drawString("no scale", left + 4, barY + barH + 10);
                g2.dispose();
                return;
            }

            // smooth gradient: white -> yellow -> orange -> red -> burgundy
            float[] fractions = {0f, 0.25f, 0.5f, 0.75f, 1f};
            Color[] stops = {
                    new Color(255, 255, 255), new Color(250, 220, 90),
                    new Color(255, 160, 60), new Color(255, 90, 90), new Color(140, 20, 40)
            };
            g2.setPaint(new LinearGradientPaint(left, 0, right, 0, fractions, stops));
            g2.fillRoundRect(left, barY, Math.max(1, right - left), barH, barH, barH);
            g2.setPaint(null);

            // tick labels
            g2.setColor(TEXT_MUTED);
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 9));
            for (int i = 0; i < TICKS.length; i++) {
                double pos = (TICK_LOG[i] - BOUNDS[0]) / span;
                int tx = left + (int) ((right - left) * pos);
                g2.drawString(TICKS[i], tx - 8, barY + barH + 10);
            }

            // thin black vertical line marker at the current IP count
            double logC = Math.log10(Math.max(count, 1));
            double pos = Math.min(1.0, Math.max(0.0, logC / BOUNDS[BOUNDS.length - 1]));
            int mx = left + (int) ((right - left) * pos);
            g2.setColor(Color.BLACK);
            g2.fillRect(mx - 1, barY - 3, 2, barH + 6);
            g2.dispose();
        }
    }

    /** Compact colored scale for the thread count (1-1000), like the IP scale. */
    private class ThreadScale extends JPanel {
        private final ThreadGauge gauge = new ThreadGauge();
        private final JLabel label = new JLabel();

        ThreadScale() {
            setOpaque(false);
            setLayout(new BorderLayout(8, 0));
            gauge.setPreferredSize(new Dimension(110, 22));
            gauge.setMinimumSize(new Dimension(90, 22));
            add(gauge, BorderLayout.WEST);
            label.setFont(new Font("Segoe UI", Font.PLAIN, 11));
            label.setForeground(TEXT_MUTED);
            add(label, BorderLayout.CENTER);
            setValue(50);
        }

        void setValue(int threads) {
            ThreadBand band = ThreadBand.forValue(threads);
            gauge.setValue(threads, true);
            Color c = gradientColor((threads - 1.0) / 1023.0);
            label.setText("<html><b style='color:rgb(" + c.getRed() + "," + c.getGreen()
                    + "," + c.getBlue() + ");'>" + threads + " network threads</b>  " + band.desc + "</html>");
        }
    }

    private enum ThreadBand {
        LIGHT(new Color(88, 230, 140), "Light"),
        NORMAL(new Color(170, 230, 90), "Normal"),
        HEAVY(new Color(250, 200, 90), "Heavy - many sockets"),
        VERY_HEAVY(new Color(255, 105, 105), "Very heavy - may exhaust sockets");

        final Color color;
        final String desc;

        ThreadBand(Color color, String desc) {
            this.color = color;
            this.desc = desc;
        }

        static ThreadBand forValue(int threads) {
            if (threads <= 16) return LIGHT;
            if (threads <= 64) return NORMAL;
            if (threads <= 256) return HEAVY;
            return VERY_HEAVY;
        }
    }

    /** Horizontal linear gauge for the network thread count 1-1024. */
    private static class ThreadGauge extends JComponent {
        private static final double[] BOUNDS = {1, 16, 64, 256, 1024};

        private int value = 50;

        void setValue(int value, boolean valid) {
            this.value = value;
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth();
            int h = getHeight();
            int left = 6;
            int right = w - 6;
            int barY = h / 2 - 4;
            int barH = 8;
            double span = BOUNDS[BOUNDS.length - 1] - BOUNDS[0];

            float[] fractions = {0f, 0.25f, 0.5f, 0.75f, 1f};
            Color[] stops = {
                    new Color(255, 255, 255), new Color(250, 220, 90),
                    new Color(255, 160, 60), new Color(255, 90, 90), new Color(140, 20, 40)
            };
            g2.setPaint(new LinearGradientPaint(left, 0, right, 0, fractions, stops));
            g2.fillRoundRect(left, barY, Math.max(1, right - left), barH, barH, barH);
            g2.setPaint(null);

            // thin black vertical line marker at the current thread count
            double pos = Math.min(1.0, Math.max(0.0, (value - BOUNDS[0]) / span));
            int mx = left + (int) ((right - left) * pos);
            g2.setColor(Color.BLACK);
            g2.fillRect(mx - 1, barY - 3, 2, barH + 6);
            g2.dispose();
        }
    }

    /** Custom scan progress bar: yellow fill, thin white edge line, 5% ticks. */
    private static class ScanProgressBar extends JComponent {
        private double pct = 0;

        ScanProgressBar() {
            setOpaque(false);
        }

        void setProgress(double pct) {
            this.pct = Math.max(0, Math.min(100, pct));
            repaint();
        }

        @Override
        protected void paintComponent(Graphics g) {
            Graphics2D g2 = (Graphics2D) g.create();
            g2.setRenderingHint(RenderingHints.KEY_ANTIALIASING, RenderingHints.VALUE_ANTIALIAS_ON);
            int w = getWidth();

            int left = 8;
            int right = Math.max(left + 1, w - 8);
            int barY = 14;
            int barH = 16;
            int barW = right - left;

            // ---- track ----
            g2.setColor(BG_FIELD);
            g2.fillRoundRect(left, barY, barW, barH, barH, barH);
            g2.setColor(BORDER);
            g2.drawRoundRect(left, barY, barW, barH, barH, barH);

            // ---- yellow fill ----
            int fillW = (int) Math.round(barW * pct / 100.0);
            if (fillW > 0) {
                g2.setPaint(new LinearGradientPaint(left, barY, left, barY + barH,
                        new float[]{0f, 1f},
                        new Color[]{new Color(255, 215, 90), new Color(240, 180, 50)}));
                g2.fillRoundRect(left, barY, Math.min(fillW, barW), barH, barH, barH);
                g2.setPaint(null);
            }

            // ---- thin white vertical line at the end of the yellow fill, inside the bar ----
            int mx = Math.max(left + 1, Math.min(right - 1, left + fillW));
            g2.setColor(Color.WHITE);
            g2.fillRect(mx - 1, barY + 1, 2, barH - 2);

            // ---- current percent text (centered; color chosen where the text's
            //      center lands: dark on fill, light on track) ----
            String pctStr = String.format(Locale.US, "%.3f%%", pct);
            g2.setFont(new Font("Segoe UI", Font.BOLD, 11));
            FontMetrics fm = g2.getFontMetrics();
            int tw = fm.stringWidth(pctStr);
            int tx = left + (barW - tw) / 2;
            int ty = barY + barH / 2 + fm.getAscent() / 2 - 1;
            boolean textOverFill = tx + tw / 2 <= left + fillW;
            g2.setColor(textOverFill ? new Color(20, 21, 30) : TEXT_MAIN);
            g2.drawString(pctStr, tx, ty);

            // ---- ticks: minor every 5%, major (with labels) at 0/25/50/75/100 ----
            g2.setFont(new Font("Segoe UI", Font.PLAIN, 9));
            FontMetrics fmT = g2.getFontMetrics();
            for (int t = 0; t <= 100; t += 5) {
                int tx2 = left + (int) (barW * t / 100.0);
                boolean major = t % 25 == 0;
                g2.setColor(major ? BORDER : BORDER.darker());
                g2.fillRect(tx2 - 1, barY + barH + 3, 2, major ? 5 : 3);
                if (major) {
                    String lbl = t + "%";
                    int lw = fmT.stringWidth(lbl);
                    g2.setColor(TEXT_MUTED);
                    g2.drawString(lbl, Math.max(left, Math.min(right - lw, tx2 - lw / 2)), barY + barH + 16);
                }
            }

            g2.dispose();
        }
    }

    public static void main(String[] args) {
        try {
            UIManager.setLookAndFeel(UIManager.getSystemLookAndFeelClassName());
            // force dark-ish defaults where possible
            UIManager.put("ToolTip.background", BG_PANEL_2);
            UIManager.put("ToolTip.foreground", TEXT_MAIN);
            UIManager.put("ToolTip.border", BorderFactory.createLineBorder(BORDER));
            // ComboBox: white text on gray, never white-on-white
            UIManager.put("ComboBox.background", new ColorUIResource(BG_FIELD));
            UIManager.put("ComboBox.foreground", new ColorUIResource(TEXT_MAIN));
            UIManager.put("ComboBox.selectionBackground", new ColorUIResource(ACCENT_DARK));
            UIManager.put("ComboBox.selectionForeground", new ColorUIResource(Color.WHITE));
            UIManager.put("ComboBox.buttonBackground", new ColorUIResource(BG_FIELD));
            UIManager.put("ComboBox.buttonForeground", new ColorUIResource(TEXT_MAIN));
        } catch (Exception ignored) {
        }
        SwingUtilities.invokeLater(IpParserGUI::new);
    }
}
