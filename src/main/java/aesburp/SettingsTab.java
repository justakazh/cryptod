package aesburp;

import burp.api.montoya.MontoyaApi;

import javax.swing.*;
import javax.swing.border.EmptyBorder;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;

/**
 * The "Cryptod" suite tab: configure key/mode/IV/encoding and test a ciphertext
 * round-trip against the current settings.
 */
public class SettingsTab {

    private final AesConfig cfg;
    private final MontoyaApi api;
    private final AesCrypto crypto;
    private final JPanel root = new JPanel(new BorderLayout());

    private final JTextField keyField = new JTextField(40);
    private final JComboBox<AesConfig.Fmt> keyFmt = new JComboBox<>(AesConfig.Fmt.values());
    private final JComboBox<AesConfig.Mode> mode = new JComboBox<>(AesConfig.Mode.values());
    private final JComboBox<AesConfig.Padding> padding = new JComboBox<>(AesConfig.Padding.values());
    private final JTextField ivField = new JTextField(40);
    private final JComboBox<AesConfig.Fmt> ivFmt = new JComboBox<>(AesConfig.Fmt.values());
    private final JCheckBox ivPrepended = new JCheckBox("IV / nonce prepended to ciphertext");
    private final JTextField gcmTag = new JTextField(6);
    private final JTextField gcmNonce = new JTextField(6);
    private final JComboBox<AesConfig.Encoding> encoding = new JComboBox<>(AesConfig.Encoding.values());

    private final JTextArea testIn = new JTextArea(7, 34);
    private final JTextArea testOut = new JTextArea(7, 34);
    private final JCheckBox testUrl = new JCheckBox("ciphertext is URL-encoded (auto decode/encode)");

    public SettingsTab(AesConfig cfg, MontoyaApi api) {
        this.cfg = cfg;
        this.api = api;
        this.crypto = new AesCrypto(cfg);
        build();
        pull();
    }

    public Component getUi() {
        return root;
    }

    private static final Color ACCENT = new Color(0xE8, 0x7B, 0x35); // Burp orange
    private static final Color LINK = new Color(0x2E, 0x8B, 0xE0);

    private void build() {
        root.add(banner(), BorderLayout.NORTH);

        JPanel content = new JPanel(new GridBagLayout());
        content.setBorder(new EmptyBorder(10, 12, 10, 12));
        GridBagConstraints o = new GridBagConstraints();
        o.gridx = 0;
        o.weightx = 1;
        o.fill = GridBagConstraints.HORIZONTAL;
        o.anchor = GridBagConstraints.NORTHWEST;
        o.insets = new Insets(0, 0, 12, 0);

        o.gridy = 0;
        content.add(configPanel(), o);
        o.gridy = 1;
        content.add(testPanel(), o);

        // vertical glue: keep both panels anchored to the top
        o.gridy = 2;
        o.weighty = 1;
        o.fill = GridBagConstraints.BOTH;
        JPanel glue = new JPanel();
        glue.setOpaque(false);
        content.add(glue, o);

        root.add(new JScrollPane(content), BorderLayout.CENTER);
    }

    private JPanel configPanel() {
        JPanel form = new JPanel(new GridBagLayout());
        form.setBorder(BorderFactory.createTitledBorder("AES configuration"));
        GridBagConstraints c = new GridBagConstraints();
        c.insets = new Insets(5, 8, 5, 8);
        int y = 0;

        y = row(form, c, y, "Key", panel(keyField, dim(new JLabel("format")), keyFmt));
        y = row(form, c, y, "Mode", panel(mode, dim(new JLabel("padding")), padding));
        y = row(form, c, y, "IV / Nonce", panel(ivField, dim(new JLabel("format")), ivFmt));
        y = row(form, c, y, "", ivPrepended);
        y = row(form, c, y, "GCM tag (bits)", panel(gcmTag, dim(new JLabel("nonce (bytes)")), gcmNonce));
        y = row(form, c, y, "Ciphertext encoding", encoding);

        JButton save = new JButton("Save settings");
        save.addActionListener(e -> {
            push();
            cfg.save(api.persistence().preferences());
            api.logging().logToOutput("Cryptod settings saved");
        });
        y = row(form, c, y, "", save);

        // filler column absorbs horizontal slack so labels/fields stay left
        GridBagConstraints f = new GridBagConstraints();
        f.gridx = 2;
        f.gridy = 0;
        f.weightx = 1;
        f.gridheight = GridBagConstraints.REMAINDER;
        f.fill = GridBagConstraints.HORIZONTAL;
        form.add(new JLabel(), f);
        return form;
    }

    private JPanel testPanel() {
        JPanel test = new JPanel(new GridBagLayout());
        test.setBorder(BorderFactory.createTitledBorder("Round-trip test"));
        GridBagConstraints t = new GridBagConstraints();
        t.insets = new Insets(6, 8, 6, 8);

        Font mono = new Font(Font.MONOSPACED, Font.PLAIN, 12);
        testIn.setLineWrap(true);
        testIn.setFont(mono);
        testOut.setLineWrap(true);
        testOut.setEditable(false);
        testOut.setFont(mono);

        JButton dec = new JButton("Decrypt ->");
        dec.addActionListener(e -> runTest(true));
        JButton enc = new JButton("<- Encrypt");
        enc.addActionListener(e -> runTest(false));

        JPanel info = new JPanel(new FlowLayout(FlowLayout.LEFT, 10, 0));
        info.add(dim(new JLabel("Uses current field values, no need to save.")));
        info.add(testUrl);
        t.gridx = 0; t.gridy = 0; t.gridwidth = 3; t.anchor = GridBagConstraints.WEST;
        test.add(info, t);

        t.gridwidth = 1; t.anchor = GridBagConstraints.CENTER;
        t.gridy = 1; t.fill = GridBagConstraints.BOTH; t.weightx = 1; t.weighty = 1;
        test.add(new JScrollPane(testIn), t);
        t.gridx = 1; t.fill = GridBagConstraints.NONE; t.weightx = 0; t.weighty = 0;
        test.add(box(dec, enc), t);
        t.gridx = 2; t.fill = GridBagConstraints.BOTH; t.weightx = 1; t.weighty = 1;
        test.add(new JScrollPane(testOut), t);
        return test;
    }

    /** Title + author + clickable GitHub link. */
    private JPanel banner() {
        JLabel title = new JLabel("Cryptod");
        title.setFont(title.getFont().deriveFont(Font.BOLD, 24f));
        title.setForeground(ACCENT);

        JLabel subtitle = dim(new JLabel("AES encrypt / decrypt for Burp Suite"));

        JLabel author = new JLabel("by Justakazh");
        author.setFont(author.getFont().deriveFont(Font.BOLD));

        JLabel link = new JLabel("https://github.com/justakazh");
        link.setForeground(LINK);
        link.setCursor(Cursor.getPredefinedCursor(Cursor.HAND_CURSOR));
        link.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                openUrl("https://github.com/justakazh");
            }
        });

        JPanel text = new JPanel();
        text.setLayout(new BoxLayout(text, BoxLayout.Y_AXIS));
        text.setOpaque(false);
        for (JComponent x : new JComponent[]{title, subtitle, author, link}) {
            x.setAlignmentX(Component.LEFT_ALIGNMENT);
            text.add(x);
        }

        JPanel bar = new JPanel(new BorderLayout());
        bar.setBorder(new EmptyBorder(12, 14, 12, 14));
        bar.add(text, BorderLayout.WEST);
        bar.add(new JSeparator(), BorderLayout.SOUTH);
        return bar;
    }

    private void openUrl(String url) {
        try {
            Desktop.getDesktop().browse(new URI(url));
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(root, url, "Cryptod", JOptionPane.INFORMATION_MESSAGE);
        }
    }

    private static JLabel dim(JLabel l) {
        l.setForeground(l.getForeground().darker());
        l.setFont(l.getFont().deriveFont(l.getFont().getSize2D() - 1f));
        return l;
    }

    /** true = decrypt testIn into testOut; false = encrypt testIn into testOut. */
    private void runTest(boolean decrypt) {
        push();
        try {
            String in = testIn.getText();
            if (decrypt) {
                if (testUrl.isSelected()) in = URLDecoder.decode(in, StandardCharsets.UTF_8);
                testOut.setText(crypto.decrypt(in));
            } else {
                String out = crypto.encrypt(in);
                if (testUrl.isSelected()) out = URLEncoder.encode(out, StandardCharsets.UTF_8);
                testOut.setText(out);
            }
        } catch (Exception ex) {
            testOut.setText("[error] " + ex.getClass().getSimpleName() + ": " + ex.getMessage());
        }
    }

    /** UI -> config. */
    private void push() {
        cfg.key = keyField.getText();
        cfg.keyFormat = (AesConfig.Fmt) keyFmt.getSelectedItem();
        cfg.mode = (AesConfig.Mode) mode.getSelectedItem();
        cfg.padding = (AesConfig.Padding) padding.getSelectedItem();
        cfg.iv = ivField.getText();
        cfg.ivFormat = (AesConfig.Fmt) ivFmt.getSelectedItem();
        cfg.ivPrepended = ivPrepended.isSelected();
        cfg.gcmTagBits = parseInt(gcmTag.getText(), cfg.gcmTagBits);
        cfg.gcmNonceLen = parseInt(gcmNonce.getText(), cfg.gcmNonceLen);
        cfg.encoding = (AesConfig.Encoding) encoding.getSelectedItem();
    }

    /** config -> UI. */
    private void pull() {
        keyField.setText(cfg.key);
        keyFmt.setSelectedItem(cfg.keyFormat);
        mode.setSelectedItem(cfg.mode);
        padding.setSelectedItem(cfg.padding);
        ivField.setText(cfg.iv);
        ivFmt.setSelectedItem(cfg.ivFormat);
        ivPrepended.setSelected(cfg.ivPrepended);
        gcmTag.setText(String.valueOf(cfg.gcmTagBits));
        gcmNonce.setText(String.valueOf(cfg.gcmNonceLen));
        encoding.setSelectedItem(cfg.encoding);
    }

    private static int parseInt(String s, int def) {
        try {
            return Integer.parseInt(s.trim());
        } catch (NumberFormatException e) {
            return def;
        }
    }

    private int row(JPanel p, GridBagConstraints c, int y, String label, Component field) {
        c.gridx = 0; c.gridy = y;
        c.anchor = GridBagConstraints.EAST;
        p.add(new JLabel(label), c);
        c.gridx = 1;
        c.anchor = GridBagConstraints.WEST;
        p.add(field, c);
        return y + 1;
    }

    private static JPanel panel(Component... items) {
        JPanel p = new JPanel(new FlowLayout(FlowLayout.LEFT, 6, 0));
        for (Component i : items) p.add(i);
        return p;
    }

    private static JPanel box(Component... items) {
        JPanel p = new JPanel();
        p.setLayout(new BoxLayout(p, BoxLayout.Y_AXIS));
        for (Component i : items) p.add(i);
        return p;
    }
}
