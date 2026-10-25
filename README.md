# LogGuard

A web app that finds attacks in your server logs. Upload an SSH auth log and/or a web access log and LogGuard
detects brute force, compromised logins, injection attempts, scanners and probing, scores the overall risk,
charts the activity and exports a report. It is a defensive tool for logs you own.

## Run it

Requires Python 3.9+.

```bash
python -m venv venv
# Windows: venv\Scripts\activate     Linux/macOS: source venv/bin/activate
pip install -r requirements.txt
python app.py
```

Open http://127.0.0.1:5000. Click **Run sample analysis** for an instant demo, or upload
`sample_logs/auth.log` and `sample_logs/access.log` (set the year to 2026), or your own logs.

Run the tests: `python -m unittest discover -s tests -v` (23 tests).

## Supported logs

| Log | Format | Typical path |
|---|---|---|
| SSH | OpenSSH lines in syslog format | `/var/log/auth.log` (Debian/Ubuntu), `/var/log/secure` (RHEL) |
| Web | Apache or Nginx **combined** format | `/var/log/nginx/access.log`, `/var/log/apache2/access.log` |

## Detection rules

| Rule | Trigger | Severity | MITRE |
|---|---|---|---|
| Successful SSH login after failures | 3+ failures from an IP within 10 min before a success | Critical | T1078 |
| SSH brute force | 5+ failures from one IP within 5 min | High | T1110 |
| SSH username enumeration | 3+ distinct unknown usernames from one IP | Medium | T1087 |
| SQL injection | Injection patterns in the URL (decoded twice) | High if any request returned 200, else Medium | T1190 |
| Path traversal / command injection | Traversal or shell patterns in the URL | High if 200, else Medium | T1190 |
| Cross-site scripting | Script or event-handler patterns in the URL | Medium | T1190 |
| Scanner traffic | sqlmap, nikto, nmap, gobuster and similar user agents | Medium | T1595 |
| 404 burst | 20+ 404 responses from one IP within 60 s | Medium | T1595 |
| Sensitive path probing | `/.env`, `/.git/`, `/wp-login.php`, `/phpmyadmin`, admin pages | Low | T1595 |

Thresholds live in the `CFG` dictionary and patterns at the top of `detectors.py`. The risk score adds
25 / 10 / 4 / 1 points per Critical / High / Medium / Low finding, capped at 100.

## Project structure

```
loguard/
  app.py            Flask routes, storage, exports, security
  parsers.py        SSH and web log parsers
  detectors.py      Detection rules, scoring, timeline
  sample_data.py    Deterministic fictional logs for demos and tests
  templates/        Jinja2 pages (SVG charts, no JavaScript)
  static/style.css
  sample_logs/      Ready-made auth.log and access.log
  tests/            23 automated tests
  data/             SQLite database (created on first run)
```

## Security design

- Binds to 127.0.0.1 by default; **no user accounts**, so do not expose it to the internet without adding authentication and HTTPS.
- Raw logs are processed in memory and never saved. Only findings (with up to three evidence lines each) are stored.
- 5 MB limit per file, binary files rejected, line cap, IP addresses validated.
- CSRF token on every POST, parameterised SQL, auto-escaped output (log content cannot inject HTML), CSV export protected against formula injection.
- Strict headers: CSP with `script-src 'none'`, X-Frame-Options, nosniff, no-store.

## Limits

- Rule-based detection on URL and user-agent patterns, so it can miss obfuscated attacks and can flag harmless requests. Treat findings as leads to investigate, not proof.
- POST bodies are not in access logs, so attacks sent in a body are invisible.
- Syslog lines have no year, so you supply it. Mixed time zones across files are not normalised.
- SQLite and the built-in server suit one analyst, not many users.

## Ideas to extend it

Add rules in `detectors.py` (RDP, FTP, firewall logs), import Wazuh alert JSON, GeoIP lookup, IP reputation lists, email alerts, or login for multi-user use.
