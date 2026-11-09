# RiskGuard SecureDB 

RiskGuard SecureDB is an educational Flask application combining a student risk register with a defensive, rule-based SQL query analyzer. This edition removes Gemini and all external AI integration. The analyzer works locally and does not execute submitted SQL.

<img width="1600" height="848" alt="image" src="https://github.com/user-attachments/assets/4c412ee0-d332-4b73-8cc3-b6e243ac3301" />
<img width="1600" height="767" alt="image" src="https://github.com/user-attachments/assets/244b63d6-1dda-4ab2-a1cd-802fd921b1ac" />
<img width="1600" height="803" alt="image" src="https://github.com/user-attachments/assets/9fcd3e05-4a60-4c10-88b2-32571898833c" />

## Features retained

- Flask + Flask-SQLAlchemy + SQLite.
- Password hashing, session-based authentication, and student/administrator role separation.
- Student profiles and account linking.
- Risk assessments scored as probability × impact.
- Severity bands: Low (<5), Medium (5–9), High (10–16), Critical (17–25).
- Admin dashboard, student register, risk register, and mitigation tracking.
- SQL static checks for dynamic SQL construction, tautology-like conditions, destructive statements, unbounded UPDATE/DELETE, `SELECT *`, broad privileges, possible hardcoded secrets, PII field references, and schema enumeration patterns.
- Per-user scan history and authenticated JSON endpoint at `/api/scan`.
- Persistent dark/black and light themes, with a toggle in the top navigation. Theme preference is stored in the browser.

## Requirements

- Windows 10/11
- Python 3.10 or newer (Python 3.11 recommended)
- VS Code with the Python extension

## Run in VS Code (Windows Command Prompt)

1. Extract the ZIP file.
2. In VS Code, choose **File → Open Folder** and select the extracted `RiskGuard_SecureDB` folder (the folder containing `app.py`).
3. Choose **Terminal → New Terminal**. If the terminal is PowerShell, open the dropdown beside the plus icon and select **Command Prompt**.
4. Create a virtual environment:

   ```bat
   py -m venv .venv
   ```

5. Activate it:

   ```bat
   .venv\Scripts\activate.bat
   ```

   The terminal prompt should now begin with `(.venv)`.

6. Install the packages:

   ```bat
   python -m pip install --upgrade pip
   python -m pip install -r requirements.txt
   ```

7. Create your local environment file by copying the example:

   ```bat
   copy .env.example .env
   ```

8. Open `.env` in VS Code and change at least:
   - `FLASK_SECRET_KEY` to a long, random private value.
   - `ADMIN_EMAIL` to the administrator email you want.
   - `ADMIN_PASSWORD` to a unique password of at least 16 characters.

   `DATABASE_URL` can remain `sqlite:///riskguard.db`. There is no Gemini key or AI model setting in this edition. Keep `.env` private and do not upload it to GitHub.

9. Start the application:

   ```bat
   python app.py
   ```

10. Open this address in your browser:

    http://127.0.0.1:5000

Keep the terminal open while using the site. Press `Ctrl+C` in the terminal to stop Flask.

## Important folder-location note

Run commands from the inner `RiskGuard_SecureDB` folder—the folder where `app.py` and `requirements.txt` are located. If Python reports that it cannot find `app.py`, check the current directory with:

```bat
dir
```

The output should include `app.py`, `analyzer.py`, `requirements.txt`, `templates`, and `static`.

## First login and demo data

- The app creates illustrative demo student profiles and risk assessments when the database is first initialized.
- The admin account is created from `ADMIN_EMAIL` and `ADMIN_PASSWORD` the first time the app initializes, provided no account with that email already exists.
- Public registration creates student accounts only.
- An administrator can create student profiles and link a registered student login by matching its email.
- If an admin account already exists, changing the values in `.env` does not reset that account's password.
- The local SQLite database is created under `instance/`. To reset all local demo data, stop the server and delete `instance/riskguard.db`, then restart. This permanently deletes local users, scans, student profiles, and assessments.

## Test the SQL analyzer

Sign in and open **SQL Analyzer**. Try these examples (they are analyzed as text only):

```sql
SELECT name, email FROM students WHERE student_id = 101;
SELECT * FROM users WHERE username = 'admin' OR 1=1;
DROP TABLE demo_table;
DELETE FROM students;
SELECT email, phone, address FROM students;
```

The analyzer reports heuristic indicators, severity, evidence, and defensive recommendations. It does not connect to a database or execute the query.

## API example

After login, send a POST request with JSON to `/api/scan`:

```json
{"query":"SELECT * FROM students"}
```

The endpoint requires an authenticated session and returns heuristic findings.

## Theme

Use the **Dark / Light** control in the top navigation. The selected theme is saved in browser local storage and remains selected on later visits in that browser.

## Security boundaries

- This is an educational prototype, not a certified database vulnerability scanner.
- Static pattern checks can produce false positives and false negatives. They do not prove exploitability or prove that an application is secure.
- Never paste production queries containing personal data, credentials, tokens, or proprietary information.
- Use synthetic data and systems you are authorized to assess.
- Before production deployment, add CSRF protection, rate limiting, security headers, secure cookie settings, HTTPS, audit logging, backups, dependency scanning, and a production WSGI server. Do not expose Flask's development server to the public internet.
- For more rigorous analysis, add dialect-aware SQL parsing, AST analysis, source-code context, unit tests, and controlled integration tests.

## Resume description

**RiskGuard SecureDB — Student Risk Management & SQL Security Analyzer**

- Built a Flask/SQLAlchemy application with role-based access, student risk registers, and probability × impact scoring.
- Implemented heuristic detection for SQL injection indicators, destructive SQL, overbroad data retrieval, privilege risks, PII exposure, and unsafe query patterns.
- Added authenticated scan history and severity-based findings with defensive remediation guidance.
- Implemented persistent dark and light themes.
- Designed the analyzer to inspect query text without executing it; documented false-positive and false-negative limitations.

Only claim features you have personally run and verified.
