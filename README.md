# Cryptod - AES encrypt/decrypt for Burp Suite

Cryptod decrypts and re-encrypts AES ciphertext inline while you test, so you do
not have to copy ciphertext out to an external tool. Configure your AES
parameters once, then work directly on a selected ciphertext in any HTTP message
editor.

## How it works

You set the AES parameters in the "Cryptod" tab: key (UTF-8/Hex/Base64), mode
(CBC, GCM, or ECB), padding, IV/nonce (with an option for an IV/nonce prepended
to the ciphertext), GCM tag and nonce length, and how the ciphertext is encoded
in the message (Base64, Base64-URL, or Hex). All cryptography is performed
locally using the JDK's `javax.crypto`; the extension makes no network
connections. Your settings are saved via Burp's extension preferences and
persist across restarts.

When you select a ciphertext in a message editor and trigger an action, Cryptod
decodes the configured encoding (URL-decoding first if the selection is
URL-encoded), decrypts it with your parameters, and shows the plaintext. When
you edit and re-encrypt, it encrypts your edited plaintext, re-applies the
configured encoding (and URL-encoding if the original was URL-encoded), and
writes the result back over exactly the bytes you selected.

## Features

- **Cryptod settings tab** - configure key, mode (CBC / GCM / ECB), padding,
  IV / nonce (with a "prepended to ciphertext" option), GCM tag/nonce length, and
  ciphertext encoding (Base64 / Base64-URL / Hex). Settings persist across restarts.
  A built-in round-trip test box validates the configuration before you touch traffic.
- **Right-click on a selected ciphertext** (Proxy, Repeater, etc.):
  - *Decrypt selection (view)* - shows the plaintext in a coloured, word-wrapped popup
    (JSON is indented; JSON and form data are syntax-highlighted like Burp's Pretty view).
  - *Decrypt, edit & re-encrypt* - edit the plaintext and write the new ciphertext back
    over exactly the selected bytes (supports undo/redo).
  - *Encrypt selection & replace* - treat the selection as plaintext and replace it.
- **Hotkeys** (HTTP message editor, with a selection):
  - `Ctrl+Shift+1` - decrypt selection (view)
  - `Ctrl+Shift+2` - decrypt, edit & re-encrypt
  - `Ctrl+Shift+3` - encrypt selection & replace
  - The same commands also appear in Burp's command palette.
- **AES editor tab** next to Raw/Pretty/Hex - decrypts the whole message body
  (handy for responses whose entire body is one ciphertext). Read-only on responses
  (JSON is indented); editable and byte-exact on requests.
- URL-encoded selections (`%2F..`) are URL-decoded before decrypting and
  URL-encoded again after encrypting, automatically.

## Build

Requires JDK 17+ and Burp with the Montoya hotkey API (2025 or later). The
extension is built against Montoya API 2026.4 and bundles no third-party
dependencies (Burp provides the Montoya API at runtime).

Using the Gradle wrapper (no local Gradle install required):

    ./gradlew jar
    # output: build/libs/cryptod-1.0.0.jar

## Install

Burp -> Extensions -> Add -> Extension type: Java -> select the built jar.

## Usage

1. Open the **Cryptod** tab and enter your AES parameters. For AES-128/192/256 the
   key must be 16/24/32 bytes in the chosen key format. Use the round-trip test box
   to confirm the configuration decrypts a known sample.
2. In any message editor, select the ciphertext value only (for a URL-encoded
   parameter value, select just the value).
3. Right-click and choose a Cryptod action, or press the matching hotkey.

## Security / privacy

Cryptod performs all cryptography locally using the JDK's `javax.crypto`. It makes
no network connections and stores only the AES parameters you enter (via Burp's
extension preferences). Treat message content as untrusted: all decrypt/encrypt
operations are wrapped so malformed input surfaces as an error dialog rather than
crashing Burp.

## License

MIT - see LICENSE.
