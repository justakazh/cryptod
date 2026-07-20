package aesburp;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;
import burp.api.montoya.ui.Selection;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.RawEditor;
import burp.api.montoya.ui.editor.extension.EditorCreationContext;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpRequestEditor;
import burp.api.montoya.ui.editor.extension.ExtensionProvidedHttpResponseEditor;
import burp.api.montoya.ui.editor.extension.HttpRequestEditorProvider;
import burp.api.montoya.ui.editor.extension.HttpResponseEditorProvider;

import java.awt.Component;
import java.nio.charset.StandardCharsets;

/**
 * Provides the "AES" editor tab for both requests and responses. Uses a RawEditor
 * (native message editors cannot be embedded in a custom editor tab - doing so
 * makes Burp render this same tab recursively and stack tabs forever).
 * Requests: editable; edits are re-encrypted into the body on forward (raw, so the
 * round-trip stays byte-exact). Responses: read-only, JSON is indented for reading.
 */
public class AesEditor {

    public static class RequestProvider implements HttpRequestEditorProvider {
        private final MontoyaApi api;
        private final AesConfig cfg;

        public RequestProvider(MontoyaApi api, AesConfig cfg) {
            this.api = api;
            this.cfg = cfg;
        }

        @Override
        public ExtensionProvidedHttpRequestEditor provideHttpRequestEditor(EditorCreationContext ctx) {
            return new RequestEditor(api, cfg);
        }
    }

    public static class ResponseProvider implements HttpResponseEditorProvider {
        private final MontoyaApi api;
        private final AesConfig cfg;

        public ResponseProvider(MontoyaApi api, AesConfig cfg) {
            this.api = api;
            this.cfg = cfg;
        }

        @Override
        public ExtensionProvidedHttpResponseEditor provideHttpResponseEditor(EditorCreationContext ctx) {
            return new ResponseEditor(api, cfg);
        }
    }

    // --- request editor (editable, raw) ---

    static class RequestEditor implements ExtensionProvidedHttpRequestEditor {
        private final AesConfig cfg;
        private final AesCrypto crypto;
        private final RawEditor editor;
        private HttpRequestResponse rr;
        private boolean decryptOk = false;

        RequestEditor(MontoyaApi api, AesConfig cfg) {
            this.cfg = cfg;
            this.crypto = new AesCrypto(cfg);
            this.editor = api.userInterface().createRawEditor(EditorOptions.WRAP_LINES);
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.rr = requestResponse;
            try {
                editor.setContents(ByteArray.byteArray(crypto.decrypt(requestResponse.request().bodyToString().trim())));
                decryptOk = true;
            } catch (Exception e) {
                editor.setContents(ByteArray.byteArray("[AES] decrypt error: " + e.getMessage()));
                decryptOk = false;
            }
        }

        @Override
        public HttpRequest getRequest() {
            HttpRequest req = rr.request();
            if (!decryptOk || !editor.isModified()) return req;
            try {
                String plain = new String(editor.getContents().getBytes(), StandardCharsets.UTF_8);
                return req.withBody(crypto.encrypt(plain));
            } catch (Exception e) {
                return req;
            }
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (!cfg.isReady() || requestResponse.request() == null) return false;
            String body = requestResponse.request().bodyToString();
            return body != null && !body.isEmpty();
        }

        @Override
        public String caption() {
            return "AES";
        }

        @Override
        public Component uiComponent() {
            return editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return editor.isModified();
        }
    }

    // --- response editor (read-only) ---

    static class ResponseEditor implements ExtensionProvidedHttpResponseEditor {
        private final AesConfig cfg;
        private final AesCrypto crypto;
        private final RawEditor editor;
        private HttpRequestResponse rr;

        ResponseEditor(MontoyaApi api, AesConfig cfg) {
            this.cfg = cfg;
            this.crypto = new AesCrypto(cfg);
            this.editor = api.userInterface().createRawEditor(EditorOptions.READ_ONLY, EditorOptions.WRAP_LINES);
        }

        @Override
        public void setRequestResponse(HttpRequestResponse requestResponse) {
            this.rr = requestResponse;
            try {
                String plain = crypto.decrypt(requestResponse.response().bodyToString().trim());
                if (Pretty.looksJson(plain)) plain = Pretty.prettyJson(plain);
                editor.setContents(ByteArray.byteArray(plain));
            } catch (Exception e) {
                editor.setContents(ByteArray.byteArray("[AES] decrypt error: " + e.getMessage()));
            }
        }

        @Override
        public HttpResponse getResponse() {
            return rr.response();
        }

        @Override
        public boolean isEnabledFor(HttpRequestResponse requestResponse) {
            if (!cfg.isReady() || requestResponse.response() == null) return false;
            String body = requestResponse.response().bodyToString();
            return body != null && !body.isEmpty();
        }

        @Override
        public String caption() {
            return "AES";
        }

        @Override
        public Component uiComponent() {
            return editor.uiComponent();
        }

        @Override
        public Selection selectedData() {
            return editor.selection().orElse(null);
        }

        @Override
        public boolean isModified() {
            return editor.isModified();
        }
    }
}
