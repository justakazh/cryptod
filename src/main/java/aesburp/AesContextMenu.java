package aesburp;

import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;

import javax.swing.*;
import java.awt.Component;
import java.awt.event.KeyEvent;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

/**
 * Right-click actions on a text selection in a message editor. All work is done
 * in {@link AesActions}, shared with the hotkey handlers.
 */
public class AesContextMenu implements ContextMenuItemsProvider {

    private final AesActions actions;
    private final AesConfig cfg;

    public AesContextMenu(AesActions actions, AesConfig cfg) {
        this.actions = actions;
        this.cfg = cfg;
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        Optional<MessageEditorHttpRequestResponse> opt = event.messageEditorRequestResponse();
        if (opt.isEmpty() || !cfg.isReady()) return Collections.emptyList();
        MessageEditorHttpRequestResponse m = opt.get();
        if (!AesActions.hasSelection(m)) return Collections.emptyList();

        List<Component> items = new ArrayList<>();

        JMenuItem view = new JMenuItem("Cryptod: Decrypt selection (view)");
        view.setMnemonic(KeyEvent.VK_D);
        view.addActionListener(e -> actions.view(m));
        items.add(view);

        if (AesActions.isRequest(m)) {
            JMenuItem edit = new JMenuItem("Cryptod: Decrypt, edit & re-encrypt");
            edit.setMnemonic(KeyEvent.VK_E);
            edit.addActionListener(e -> actions.editReEncrypt(m));
            items.add(edit);

            JMenuItem enc = new JMenuItem("Cryptod: Encrypt selection & replace");
            enc.setMnemonic(KeyEvent.VK_N);
            enc.addActionListener(e -> actions.encryptReplace(m));
            items.add(enc);
        }

        return items;
    }
}
