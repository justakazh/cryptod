package aesburp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Range;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse.SelectionContext;

import javax.swing.*;
import java.awt.Frame;
import javax.swing.event.DocumentEvent;
import javax.swing.event.DocumentListener;
import javax.swing.text.AbstractDocument;
import javax.swing.text.BadLocationException;
import javax.swing.text.BoxView;
import javax.swing.text.ComponentView;
import javax.swing.text.Element;
import javax.swing.text.IconView;
import javax.swing.text.LabelView;
import javax.swing.text.ParagraphView;
import javax.swing.text.SimpleAttributeSet;
import javax.swing.text.StyleConstants;
import javax.swing.text.StyledDocument;
import javax.swing.text.StyledEditorKit;
import javax.swing.text.View;
import javax.swing.text.ViewFactory;
import javax.swing.undo.UndoManager;
import javax.swing.undo.UndoableEdit;
import java.awt.Color;
import java.awt.Dimension;
import java.awt.Font;
import java.awt.Toolkit;
import java.awt.event.ActionEvent;
import java.awt.event.InputEvent;
import java.awt.event.KeyEvent;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * The three selection-based operations, shared by the context menu and hotkeys.
 * Popups show only the decrypted data (no HTTP status line) with JSON/form
 * colouring - native Burp editors cannot be used here (they force a status line
 * and, when embedded, recurse into this same tab).
 *
 * URL-encoded selections (containing '%') are URL-decoded before decrypting and
 * URL-encoded again after encrypting.
 */
public class AesActions {

    private final AesCrypto crypto;
    private final Frame parent; // dialogs must be children of the Burp suite frame

    public AesActions(MontoyaApi api, AesConfig cfg) {
        this.crypto = new AesCrypto(cfg);
        this.parent = api.userInterface().swingUtils().suiteFrame();
    }

    public static boolean hasSelection(MessageEditorHttpRequestResponse m) {
        return m.selectionOffsets().isPresent();
    }

    public static boolean isRequest(MessageEditorHttpRequestResponse m) {
        return m.selectionContext() == SelectionContext.REQUEST;
    }

    /** Decrypt the selection and show it read-only, coloured and (if JSON) indented. */
    public void view(MessageEditorHttpRequestResponse m) {
        if (!hasSelection(m)) return;
        String plain = tryDecrypt(selectedText(m));
        if (plain == null) return;
        String shown = Pretty.looksJson(plain) ? Pretty.prettyJson(plain) : plain;

        JTextPane pane = coloredPane(shown, false);
        JScrollPane sp = new JScrollPane(pane);
        sp.setPreferredSize(new Dimension(760, 460));
        JOptionPane.showMessageDialog(parent, sp, "Decrypted", JOptionPane.PLAIN_MESSAGE);
    }

    /** Decrypt the selection, let the user edit it, then write the new ciphertext back. */
    public void editReEncrypt(MessageEditorHttpRequestResponse m) {
        if (!hasSelection(m) || !isRequest(m)) return;
        String sel = selectedText(m);
        boolean urlEnc = sel.indexOf('%') >= 0;
        String plain = tryDecrypt(sel);
        if (plain == null) return;

        // No reflow: edit the exact plaintext so the re-encrypted bytes stay faithful.
        JTextPane pane = coloredPane(plain, true);
        JScrollPane sp = new JScrollPane(pane);
        sp.setPreferredSize(new Dimension(760, 460));
        int ok = JOptionPane.showConfirmDialog(parent, sp, "Edit plaintext (re-encrypts on OK)",
                JOptionPane.OK_CANCEL_OPTION, JOptionPane.PLAIN_MESSAGE);
        if (ok != JOptionPane.OK_OPTION) return;
        replaceSelection(m, encode(pane.getText(), urlEnc));
    }

    /** Treat the selection as plaintext, encrypt it and replace it. */
    public void encryptReplace(MessageEditorHttpRequestResponse m) {
        if (!hasSelection(m) || !isRequest(m)) return;
        String sel = selectedText(m);
        boolean urlEnc = sel.indexOf('%') >= 0;
        replaceSelection(m, encode(sel, urlEnc));
    }

    // --- crypto glue ---

    static String selectedText(MessageEditorHttpRequestResponse m) {
        Range r = m.selectionOffsets().get();
        ByteArray full = isRequest(m) ? m.requestResponse().request().toByteArray()
                                      : m.requestResponse().response().toByteArray();
        return new String(full.subArray(r).getBytes(), StandardCharsets.UTF_8);
    }

    private String tryDecrypt(String selected) {
        String data = selected.indexOf('%') >= 0
                ? URLDecoder.decode(selected, StandardCharsets.UTF_8) : selected;
        try {
            return crypto.decrypt(data);
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Decrypt failed: " + ex.getMessage(),
                    "Cryptod", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    private String encode(String plaintext, boolean urlEncode) {
        try {
            String cipher = crypto.encrypt(plaintext);
            return urlEncode ? URLEncoder.encode(cipher, StandardCharsets.UTF_8) : cipher;
        } catch (Exception ex) {
            JOptionPane.showMessageDialog(parent, "Encrypt failed: " + ex.getMessage(),
                    "Cryptod", JOptionPane.ERROR_MESSAGE);
            return null;
        }
    }

    /** Splice replacement bytes over the selected range and push it back to the editor. */
    private static void replaceSelection(MessageEditorHttpRequestResponse m, String replacement) {
        if (replacement == null) return;
        Range r = m.selectionOffsets().get();
        byte[] full = m.requestResponse().request().toByteArray().getBytes();
        byte[] repl = replacement.getBytes(StandardCharsets.UTF_8);
        int start = r.startIndexInclusive();
        int end = r.endIndexExclusive();

        byte[] out = new byte[start + repl.length + (full.length - end)];
        System.arraycopy(full, 0, out, 0, start);
        System.arraycopy(repl, 0, out, start, repl.length);
        System.arraycopy(full, end, out, start + repl.length, full.length - end);

        HttpRequest orig = m.requestResponse().request();
        m.setRequest(HttpRequest.httpRequest(orig.httpService(), ByteArray.byteArray(out)));
    }

    // --- colouring ---

    // Match Burp's light-theme syntax colours.
    private static final Font MONO = new Font(Font.MONOSPACED, Font.PLAIN, 13);
    private static final SimpleAttributeSet BLUE = fg(0x00, 0x00, 0xC0);  // json numbers/atoms, form param names
    private static final SimpleAttributeSet GREEN = fg(0x00, 0x80, 0x00); // json string values
    private static final SimpleAttributeSet RED = fg(0xA0, 0x10, 0x10);   // form values

    private static final Pattern JSON_STRING = Pattern.compile("\"(?:\\\\.|[^\"\\\\])*\"");
    private static final Pattern JSON_ATOM =
            Pattern.compile("\\b(?:true|false|null)\\b|-?\\d+(?:\\.\\d+)?(?:[eE][+-]?\\d+)?");

    private static JTextPane coloredPane(String text, boolean editable) {
        JTextPane pane = new JTextPane();
        pane.setEditorKit(new WrapEditorKit()); // wrap even long unbreakable tokens
        pane.setFont(MONO);
        pane.setText(text);
        pane.setEditable(editable);
        recolor(pane.getStyledDocument());
        pane.setCaretPosition(0);
        if (editable) {
            pane.getDocument().addDocumentListener(new DocumentListener() {
                public void insertUpdate(DocumentEvent e) { schedule(pane); }
                public void removeUpdate(DocumentEvent e) { schedule(pane); }
                public void changedUpdate(DocumentEvent e) { } // attribute-only: ignore
            });
            installUndo(pane);
        }
        return pane;
    }

    /** Ctrl+Z / Ctrl+Y (Ctrl+Shift+Z) undo-redo for text edits only (recolour is skipped). */
    private static void installUndo(JTextPane pane) {
        UndoManager undo = new UndoManager();
        pane.getDocument().addUndoableEditListener(ev -> {
            UndoableEdit edit = ev.getEdit();
            if (edit instanceof AbstractDocument.DefaultDocumentEvent) {
                DocumentEvent.EventType t = ((AbstractDocument.DefaultDocumentEvent) edit).getType();
                if (t == DocumentEvent.EventType.INSERT || t == DocumentEvent.EventType.REMOVE) {
                    undo.addEdit(edit);
                }
            }
        });

        int mask = Toolkit.getDefaultToolkit().getMenuShortcutKeyMaskEx();
        var im = pane.getInputMap();
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask), "cryptod-undo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Y, mask), "cryptod-redo");
        im.put(KeyStroke.getKeyStroke(KeyEvent.VK_Z, mask | InputEvent.SHIFT_DOWN_MASK), "cryptod-redo");
        pane.getActionMap().put("cryptod-undo", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                if (undo.canUndo()) undo.undo();
            }
        });
        pane.getActionMap().put("cryptod-redo", new AbstractAction() {
            public void actionPerformed(ActionEvent e) {
                if (undo.canRedo()) undo.redo();
            }
        });
    }

    private static void schedule(JTextPane pane) {
        SwingUtilities.invokeLater(() -> recolor(pane.getStyledDocument()));
    }

    /** Reset then re-apply styles over the whole document. Never changes text. */
    private static void recolor(StyledDocument doc) {
        String text;
        try {
            text = doc.getText(0, doc.getLength());
        } catch (BadLocationException e) {
            return;
        }
        doc.setCharacterAttributes(0, text.length(), new SimpleAttributeSet(), true);
        if (Pretty.looksJson(text)) {
            styleJson(doc, text);
        } else if (Pretty.looksForm(text)) {
            styleForm(doc, text);
        }
        // plain text: leave default
    }

    /** Burp-like JSON: keys default, string values green, numbers/atoms blue. */
    private static void styleJson(StyledDocument doc, String s) {
        boolean[] inString = new boolean[s.length()];
        Matcher m = JSON_STRING.matcher(s);
        while (m.find()) {
            int end = m.end();
            for (int i = m.start(); i < end; i++) inString[i] = true;
            int j = end;
            while (j < s.length() && Character.isWhitespace(s.charAt(j))) j++;
            boolean isKey = j < s.length() && s.charAt(j) == ':';
            if (!isKey) doc.setCharacterAttributes(m.start(), end - m.start(), GREEN, true);
        }
        Matcher a = JSON_ATOM.matcher(s);
        while (a.find()) {
            if (inString[a.start()]) continue;
            doc.setCharacterAttributes(a.start(), a.end() - a.start(), BLUE, true);
        }
    }

    /** Burp-like form data: param name blue (#0000C0), value red (#A01010). */
    private static void styleForm(StyledDocument doc, String s) {
        int n = s.length(), i = 0;
        while (i < n) {
            int amp = s.indexOf('&', i);
            int end = amp < 0 ? n : amp;
            int eq = s.indexOf('=', i);
            if (eq >= 0 && eq < end) {
                doc.setCharacterAttributes(i, eq - i, BLUE, true);              // param name
                doc.setCharacterAttributes(eq + 1, end - (eq + 1), RED, true);  // value
            }
            i = amp < 0 ? n : amp + 1;
        }
    }

    private static SimpleAttributeSet fg(int r, int g, int b) {
        SimpleAttributeSet a = new SimpleAttributeSet();
        StyleConstants.setForeground(a, new Color(r, g, b));
        return a;
    }

    // --- force character-level wrapping so long tokens never scroll horizontally ---

    private static class WrapEditorKit extends StyledEditorKit {
        private final ViewFactory factory = new WrapColumnFactory();

        @Override
        public ViewFactory getViewFactory() {
            return factory;
        }
    }

    private static class WrapColumnFactory implements ViewFactory {
        @Override
        public View create(Element e) {
            String kind = e.getName();
            if (kind != null) {
                switch (kind) {
                    case AbstractDocument.ContentElementName:
                        return new WrapLabelView(e);
                    case AbstractDocument.ParagraphElementName:
                        return new ParagraphView(e);
                    case AbstractDocument.SectionElementName:
                        return new BoxView(e, View.Y_AXIS);
                    case StyleConstants.ComponentElementName:
                        return new ComponentView(e);
                    case StyleConstants.IconElementName:
                        return new IconView(e);
                    default:
                        break;
                }
            }
            return new LabelView(e);
        }
    }

    private static class WrapLabelView extends LabelView {
        WrapLabelView(Element e) {
            super(e);
        }

        @Override
        public float getMinimumSpan(int axis) {
            // returning 0 on the X axis lets the view break mid-token
            return axis == View.X_AXIS ? 0 : super.getMinimumSpan(axis);
        }
    }
}
