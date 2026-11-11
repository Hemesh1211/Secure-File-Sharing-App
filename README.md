# Secure File Sharing App

A beginner-to-intermediate cybersecurity project built with Python, Flask, SQLite, and Flask-WTF. It demonstrates account authentication, per-user authorization, CSRF protection, and safer handling of uploaded files.

> **Learning project:** intended for local use and trusted-network demonstrations. It is not production-ready and should not be exposed to the public internet.

## Features

- Register, log in, and log out
- Passwords stored as Werkzeug password hashes
- Private dashboard for each account
- Upload, download, and delete your own files
- Server-side ownership checks on every file action
- Random internal storage names; original names are display metadata
- CSRF tokens on state-changing forms
- 50 MB upload request limit
- Allowlisted extensions: `.pdf`, `.png`, `.jpg`, `.jpeg`, `.txt`, `.docx`, `.csv`
- SQLite metadata storage and basic security event logging
- Responsive interface

## How it works

1. A user registers. The app hashes the password before storing it in SQLite.
2. On login, Flask places the user ID in a signed session cookie. The cookie is `HttpOnly` and `SameSite=Lax`.
3. The dashboard queries only file records owned by the current user.
4. During upload, the app checks the extension and size, creates a random storage name, saves bytes in `uploads/` (outside `static/`), and records the owner and display name in SQLite.
5. Download and delete routes query by both file ID and the signed-in user's ID. Knowing another file's numeric ID does not grant access.
6. Flask-WTF checks CSRF tokens on POST forms such as upload, delete, and logout.

The extension allowlist is not a malware scanner and does not prove that a file's content is safe.

## Project structure

```text
Secure-File-Sharing-App/
├── app.py
├── requirements.txt
├── run_app.bat
├── .env.example
├── .gitignore
├── static/style.css
├── templates/
│   ├── base.html
│   ├── dashboard.html
│   ├── login.html
│   └── register.html
├── instance/       # Runtime database; local data is ignored by Git
└── uploads/        # Private uploaded files; contents are ignored by Git
```

## Run on Windows

### One-click launcher

Double-click `run_app.bat`. It creates a virtual environment, installs dependencies, creates a persistent local secret key, initializes SQLite, and starts Flask on port 5000. The first run requires an internet connection to install packages.

Open `http://127.0.0.1:5000` on the computer running the app. To demonstrate it on another device on the same trusted Wi-Fi, find the host computer's Wi-Fi IPv4 address with `ipconfig` and visit `http://<IPv4-address>:5000` (example: `http://192.168.1.25:5000`). If Windows Firewall asks, allow access on Private networks only. Keep the launcher window open while using the app.

### Manual PowerShell setup

```powershell
cd D:\Cyber-Security-Projects\Secure-File-Sharing-App
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
$env:FLASK_SECRET_KEY = (py -c "import secrets; print(secrets.token_hex(32))")
flask --app app init-db
flask --app app run
```

Open `http://127.0.0.1:5000`.

## Run on Linux/macOS

```bash
cd /path/to/Secure-File-Sharing-App
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
export FLASK_SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
flask --app app init-db
flask --app app run
```

Open `http://127.0.0.1:5000`. Stop the server with Ctrl+C.

## Manual security checklist

Use two test accounts and keep testing on your own local copy.

1. While logged out, visit `/dashboard` and a download URL. Protected pages should redirect to login.
2. Upload a file as User A. Log in as User B and try A's file ID in download and delete URLs. Both should return 404; A's file should remain available to A.
3. Try a disallowed extension such as `.exe`; it should be rejected. Try a file larger than 50 MB; it should be rejected.
4. Try a filename containing path components such as `../`. It should not create a file outside `uploads/`; on disk, stored files use random names.
5. Remove a form's `csrf_token` and submit its POST request. Flask-WTF should reject the request (HTTP 400).
6. Inspect `instance/app.sqlite3`: `users.password_hash` should be a hash and should not match the password you entered.
7. Log out and revisit `/dashboard`; the app should require login again.

## Publish the source on GitHub

Create an empty GitHub repository (for example, `secure-file-sharing-app`) without adding a README, then run these commands from PowerShell in this folder. Replace `YOUR_GITHUB_USERNAME` with your GitHub username:

```powershell
cd D:\Cyber-Security-Projects\Secure-File-Sharing-App
git init
git add .
git status
git commit -m "Build secure file sharing app"
git branch -M main
git remote add origin https://github.com/YOUR_GITHUB_USERNAME/secure-file-sharing-app.git
git push -u origin main
```

Review `git status` before committing. `.gitignore` excludes the virtual environment, SQLite database, uploaded content, `.env`, and local secret key. Do not force-add those files. After pushing, open the repository on GitHub and use **Pin** or **Customize your pins** on your profile to feature it. You can also add its link to a portfolio Projects section with the project description and screenshots.

GitHub stores and displays the source; **GitHub Pages cannot run this Flask backend**. A public live demo needs a separate Python hosting service, HTTPS, production server configuration, secret management, and persistent private storage. Do not deploy this current learning version as-is.

## Limitations and next steps

This is not a production service. Before any real deployment, add HTTPS, a production WSGI server, rate limiting, account recovery policy, content signature inspection, malware scanning, storage quotas, backups, monitoring, dependency update process, and a security review. The app's 50 MB setting limits an upload request but is not a storage quota. Do not expose the Flask development server to the internet. HTTP on Wi-Fi does not encrypt passwords or session traffic; use only a trusted network for demonstrations.

## Technology

Python 3 · Flask · Flask-WTF · SQLite · Werkzeug · HTML/CSS
