# HTB Sherlock: PhantomBundle

**Difficulty:** Hard  
**XP:** 1202  
**Author:** 0xS1rx58  
**Sherlock status:** Solved, player #72

## Overview

PhantomBundle is a mobile forensics challenge involving an Android triage image and a PCAP. The artifacts reveal a phishing lure, a malicious downloader, a second-stage Android trojan, and its C2 activity. The WhatsApp crypt14 backup contains the lure message; Chrome History and an offline MHTML page preserve the spoofed Google Play listing; the APKs reveal the downloader and fake banking login screen; and the PCAP contains the C2 key, commands, fraudulent notification, and stolen credentials.

This write-up analyzes only the supplied lab artifacts offline. Neither APK was executed.

## Setup and Extraction

The archive was moved to `~/htb/sherlock/PhantomBundle.zip` and extracted under `~/htb/sherlock/`. The resulting `PhantomBundle/` directory contains `capture.pcap` and `android_triage.tar.gz`. The Android filesystem image was extracted separately into `triage/`.

```bash
mkdir -p ~/htb/sherlock
mv ~/Downloads/PhantomBundle.zip ~/htb/sherlock/PhantomBundle.zip
unzip -q ~/htb/sherlock/PhantomBundle.zip -d ~/htb/sherlock

CASE=~/htb/sherlock/PhantomBundle
mkdir -p "$CASE/triage"
tar -xzf "$CASE/android_triage.tar.gz" -C "$CASE/triage"
```

Tools used: `sqlite3`, `tshark`, `androguard`, `wa-crypt-tools`, and `openssl`.

## 1. WhatsApp Message and Phishing Number

The live WhatsApp `msgstore.db` did not contain the lure. However, the triage image included both the `/data/media/0/WhatsApp/Databases/msgstore.db.crypt14` backup and its key file at `/data/data/com.whatsapp/files/key`. I decrypted the backup to `/tmp`, leaving the source artifacts untouched:

```bash
python3 -m venv /tmp/phantom-venv
/tmp/phantom-venv/bin/pip install wa-crypt-tools

/tmp/phantom-venv/bin/wadecrypt \
  "$CASE/triage/data/data/com.whatsapp/files/key" \
  "$CASE/triage/data/media/0/WhatsApp/Databases/msgstore.db.crypt14" \
  /tmp/phantom-msgstore.db
```

The decrypted SQLite backup contained an incoming message with `_id=4` in a chat associated with the sender LID `209011026690289@lid`. Joining `jid_map` (`lid_row_id=5 -> jid_row_id=6`) to `jid` resolved the phone-number identity to `201552869660@s.whatsapp.net`. Therefore, the phishing number was `+20 155 286 9660`.

```sql
SELECT m._id, m.from_me, m.timestamp, m.text_data,
       lid.raw_string AS sender_lid, phone.raw_string AS sender_phone
FROM message AS m
JOIN chat AS c ON c._id = m.chat_row_id
JOIN jid AS lid ON lid._id = c.jid_row_id
LEFT JOIN jid_map AS map ON map.lid_row_id = c.jid_row_id
LEFT JOIN jid AS phone ON phone._id = map.jid_row_id
WHERE m.from_me = 0;
```

The lure advertised a “12-Month Free Bundle” for SubHub Pro and directed the victim to install it from a Google Play lookalike site. The 513-character message stored in the backup ends with the following text; the artifact itself is truncated after `they're`:

> Spots are extremely limited – act fast before they're gone! – act fast before they're

## 2. Browser History and Spoofed Google Play Page

Chrome's `visits` and `urls` tables show the last visit to `https://play-google.hrzn.run/` at `2026-02-21 03:35:41 UTC`. The device timezone was UTC+05, so the corresponding local time was `08:35:41`.

```bash
sqlite3 -readonly "$CASE/triage/data/data/com.android.chrome/app_chrome/Default/History" \
"SELECT u.url, u.title,
        datetime(v.visit_time/1000000-11644473600,'unixepoch') AS visit_utc
 FROM visits AS v JOIN urls AS u ON u.id=v.url
 WHERE u.url LIKE '%play-google%' ORDER BY v.visit_time;"
```

Chrome had also saved an offline MHTML copy of the page under `cache/Offline Pages/archives/`. The reviewers appear in this order: Michael, Elena Smith, and Lara Croft. The last reviewer displayed was **Lara Croft**.

```bash
rg -n 'class="reviewer"' \
  "$CASE/triage/data/data/com.android.chrome/cache/Offline Pages/archives/"*.mhtml
```

## 3. Downloader and Second-Stage APK

The downloader APK uses the package name `com.service.subhubpro`. Its `MainActivity` reverses an encoded resource string, Base64-decodes it, and XORs each byte with `0x7e` to recover the download URL:

```text
https://github.com/0xS1rx58/updater/releases/download/updater/icon.png
```

Although the file is named `icon.png`, the downloader passes it to Android's package installer as an APK. It then checks for the `com.andorid.systemui` package and launches it. The spelling `andorid` is intentional here: it is the exact package name recorded in the APK manifest.

```bash
DOWNLOADER=$(find "$CASE/triage/data/app" \
  -path '*com.service.subhubpro*' -name base.apk -print -quit)
STAGE2=$(find "$CASE/triage/data/app" \
  -path '*com.andorid.systemui*' -name base.apk -print -quit)

androguard apkid "$DOWNLOADER" "$STAGE2"
androguard decompile -i "$DOWNLOADER" -o /tmp/phantom-downloader-dc
androguard decompile -i "$STAGE2" -o /tmp/phantom-stage2-dc
androguard axml -i "$STAGE2"
```

The second-stage manifest registers `com.andorid.systemui.C1AccessibilityService` as an Android `AccessibilityService`. Its `onAccessibilityEvent()` handler reads text from text-change and text-selection events, adds the package, class, and timestamp, then sends the data to C2 as a `keylog_capture` event.

When the service connects, it also creates a foreground notification with:

- Title: `System Update`
- Text: `Downloading...`

These values are the notification title and body.

## 4. Screenshot Command

In the command dispatcher, command `71` launches `ScreenshotCaptureActivity`. The activity requests screen-capture permission through `MediaProjectionManager.createScreenCaptureIntent()`, then creates a `MediaProjection` and a `VirtualDisplay` named `Screenshot` to capture the display.

**Answer:** Command `71`; component `com.andorid.systemui.ScreenshotCaptureActivity`.

## 5. C2 and Encryption

The PCAP shows the device sending HTTP POST requests to `107.189.13.21:8080` at the `/api` endpoint. The full URL is:

```text
http://107.189.13.21:8080/api
```

The following Base64-encoded key appears in `secure_prefs.xml` and in the initial `init_key` request:

```text
3BJCjd8ZFBCK/umyWUD9NuWOJE34Uq/p6Lb2kumv37k=
```

The APK's crypto helper uses `AES/CTR/NoPadding`. It prepends a random 16-byte IV to the ciphertext and Base64-encodes the result. To decrypt captured payloads, extract the HTTP body with `tshark`, Base64-decode it, use the first 16 bytes as the IV, and pass the remainder to `openssl enc -d -aes-256-ctr`.

For example, the following decrypts the HTTP response in C2 TCP stream 41:

```bash
KEY='3BJCjd8ZFBCK/umyWUD9NuWOJE34Uq/p6Lb2kumv37k='
KEY_HEX=$(printf '%s' "$KEY" | base64 -d | xxd -p -c 64)
STREAM=41
BODY_HEX=$(tshark -r "$CASE/capture.pcap" \
  -Y "tcp.stream == $STREAM && http.response" \
  -T fields -e http.file_data | head -1)
BODY=$(printf '%s' "$BODY_HEX" | xxd -r -p)
IV=$(printf '%s' "$BODY" | base64 -d | head -c 16 | xxd -p -c 32)
printf '%s' "$BODY" | base64 -d | tail -c +17 | \
  openssl enc -d -aes-256-ctr -K "$KEY_HEX" -iv "$IV"
```

The decrypted response in stream 41 contained the parameters for `command: 73`, revealing the fake notification:

- Title: `S1rBank Urgent Alert`
- Message: `Unauthorized transfer attempt: USD 2,000 from your account.`
- Priority: `high`

This aligns with the notification event timing in the PCAP.

The C2 request in stream 49 contained the stolen credentials:

```text
Username: Ali209714
Password: Ali_3691Pass5
```

## 6. Fake Banking Login Screen

`LoginActivity` displays the APK's native Android `activity_login` layout. It includes the labels `S1rBank`, `Welcome Back`, and `Secure access to your digital vault`, along with username and password fields. The slogan asked for in the task is:

```text
Next Generation Banking
```

When the victim taps Login, the click listener reads both `EditText` values and sends a C2 event containing `type=Credentials`, `Username`, and `Password`. This behavior is classified under MITRE ATT&CK Mobile's GUI Input Capture sub-technique.

## Answers

| Task | Answer |
|---|---|
| 1 | `+201552869660` (`201552869660`) |
| 2 | `2026-02-21 03:35:41 UTC` (`08:35:41 UTC+05`) |
| 3 | `Spots are extremely limited – act fast before they're gone! – act fast before they're` |
| 4 | `Lara Croft` |
| 5 | `https://github.com/0xS1rx58/updater/releases/download/updater/icon.png` |
| 6 | `com.andorid.systemui` |
| 7 | `com.andorid.systemui.C1AccessibilityService` |
| 8 | `System Update` |
| 9 | `http://107.189.13.21:8080/api` |
| 10 | `71` — `com.andorid.systemui.ScreenshotCaptureActivity` |
| 11 | `3BJCjd8ZFBCK/umyWUD9NuWOJE34Uq/p6Lb2kumv37k=` |
| 12 | `S1rBank Urgent Alert` — `Unauthorized transfer attempt: USD 2,000 from your account.` |
| 13 | Username `Ali209714`; password `Ali_3691Pass5` |
| 14 | `Next Generation Banking` |
| 15 | `T1417.002` — Mobile ATT&CK, Input Capture: GUI Input Capture |

## Key Indicators of Compromise

| Indicator | Value |
|---|---|
| Phishing site | `https://play-google.hrzn.run/` |
| Downloader URL | `https://github.com/0xS1rx58/updater/releases/download/updater/icon.png` |
| C2 | `http://107.189.13.21:8080/api` |
| Downloader package | `com.service.subhubpro` |
| Stage-two package | `com.andorid.systemui` |
| Phishing WhatsApp number | `+20 155 286 9660` |
