package aesburp;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.ui.hotkey.HotKey;
import burp.api.montoya.ui.hotkey.HotKeyContext;

public class AesExtension implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {
        api.extension().setName("Cryptod - AES encrypt/decrypt");

        AesConfig cfg = new AesConfig();
        cfg.load(api.persistence().preferences());
        AesActions actions = new AesActions(api, cfg);

        SettingsTab settings = new SettingsTab(cfg, api);
        api.userInterface().registerSuiteTab("Cryptod", settings.getUi());

        api.userInterface().registerHttpRequestEditorProvider(new AesEditor.RequestProvider(api, cfg));
        api.userInterface().registerHttpResponseEditorProvider(new AesEditor.ResponseProvider(api, cfg));

        api.userInterface().registerContextMenuItemsProvider(new AesContextMenu(actions, cfg));

        registerHotKeys(api, actions);

        // Cryptod holds no background threads or external resources; nothing to release,
        // but register a handler so the extension unloads cleanly (BApp criteria).
        api.extension().registerUnloadingHandler(
                () -> api.logging().logToOutput("Cryptod unloaded."));

        api.logging().logToOutput("Cryptod loaded (by Justakazh - https://github.com/justakazh). "
                + "Configure it in the 'Cryptod' tab, then select a ciphertext and use the "
                + "right-click menu or the Cryptod hotkeys.");
    }

    /**
     * Register default hotkeys in the HTTP message editor context. Extension hotkeys
     * are fixed here (Burp does not expose them for rebinding in Settings); the
     * commands also appear in Burp's command palette.
     */
    private void registerHotKeys(MontoyaApi api, AesActions actions) {
        var ui = api.userInterface();
        ui.registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR,
                HotKey.hotKey("Cryptod: Decrypt selection (view)", "Ctrl+Shift+1"),
                event -> event.messageEditorRequestResponse().ifPresent(actions::view));

        ui.registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR,
                HotKey.hotKey("Cryptod: Decrypt, edit & re-encrypt", "Ctrl+Shift+2"),
                event -> event.messageEditorRequestResponse().ifPresent(actions::editReEncrypt));

        ui.registerHotKeyHandler(HotKeyContext.HTTP_MESSAGE_EDITOR,
                HotKey.hotKey("Cryptod: Encrypt selection & replace", "Ctrl+Shift+3"),
                event -> event.messageEditorRequestResponse().ifPresent(actions::encryptReplace));
    }
}
