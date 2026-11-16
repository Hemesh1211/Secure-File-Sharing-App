# SecureShare — Minimal Encrypted File Sharing App (v2.2)

A clean, minimal cybersecurity project built with **Python 3, Flask, Flask-WTF, Cryptography (AES-256-GCM + HKDF-SHA256), and SQLite**, featuring a **pure-white minimal UI**, **4 built-in color palettes**, and **real-time automatic page updates**.

## Key Features

1. **Real-Time Automatic Updates (Zero Manual Refresh)**:
   - **Instant Entry Sync**: Strict `Cache-Control: no-store` headers plus `pageshow` and `visibilitychange` listeners ensure the workspace refreshes every time a user enters or returns to the site.
   - **Live Server-Sent Events (`/api/stream`) & Auto-Sync (`/api/live-state`)**: Whenever a file is uploaded, deleted, or shared by another user, the dashboard KPIs, file tables, **Shared With Me** list, and activity log update automatically in real time without refreshing the browser.
   - **Instant AJAX Upload**: Uploading a file encrypts and inserts it immediately into the table without a page reload.
2. **Minimal Pure-White Interface with 4 Built-in Color Palettes**:
   - Crisp `#FFFFFF` background with `#F8FAFC` subtle surfaces and high-contrast `#0F172A` typography.
   - Instant header palette switcher supporting **Nordic Cobalt** (`#2563EB`), **Sage Emerald** (`#059669`), **Royal Indigo** (`#4F46E5`), and **Monochrome Graphite** (`#18181B`).
3. **AES-256-GCM Envelope Encryption at Rest & SHA-256 Integrity**:
   - Every uploaded file derives a unique 256-bit key via `HKDF-SHA256` and is encrypted on disk with authenticated `AES-256-GCM` and verified against its SHA-256 checksum.

## Quick Start on Windows (`D:\Cyber-Security-Projects\Secure-File-Sharing-App`)

1. Extract `Secure-File-Sharing-App-Redesigned.zip` into `D:\Cyber-Security-Projects\Secure-File-Sharing-App`.
2. Double-click **`run_app.bat`** (or run in PowerShell):

```powershell
cd D:\Cyber-Security-Projects\Secure-File-Sharing-App
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
flask --app app init-db
flask --app app run --with-threads
```

3. Open `http://127.0.0.1:5000` in your browser.