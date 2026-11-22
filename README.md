# CyberGuard 2.0 release candidate

CyberGuard scans web URLs, SMS messages, and PNG or JPEG images with a single QR code. Reports show model contributions, rule adjustments, completed checks, and cached phishing-feed matches. Scan history stores metadata in `data/scan_history.sqlite3`.

## Setup and tests

These PowerShell commands use 64-bit Python 3.10 from the project directory.

```powershell
py -3.10 -m venv .venv
& .\.venv\Scripts\python.exe -m pip install -r requirements.txt
& .\.venv\Scripts\python.exe -X utf8 -m pytest -q
& .\.venv\Scripts\python.exe -X utf8 -m streamlit run app.py --server.address 127.0.0.1
```

The bundled models, benchmark summary, and test fixtures are sufficient for setup. The tests use offline feed fixtures.

## Phishing feed

No API key is required. On demand, CyberGuard fetches the [Phishunt text feed](https://phishunt.io/feed.txt) at most once an hour with a five-second timeout. It stores the last successful snapshot in `data/phishing_feed.sqlite3`. Submitted content is matched locally, and the report shows stale or unavailable status when applicable. The feed leaves risk scores unchanged.

## Three-minute demo

| Time | What to show |
| --- | --- |
| 0:00 | From **Dashboard**, scan `https://example.com`. Compare the model flag with the overall risk score and open **Risk score changes**. |
| 0:45 | Scan `Meeting details: https://example.com/Agenda` as an SMS. Review its model explanation and the separate embedded URL check. |
| 1:30 | Open **QR Image** and upload `tests/fixtures/qr/url.png`. Review the decoded URL and the QR entry in **Scan History**. |
| 2:15 | Open **Analytics**, filter by input type, then review the locked Stage 3B results. The calibrated linear SVM is an offline SMS spam detection benchmark candidate. The deployed SMS scanner uses a separate TF-IDF logistic regression and risk rules. |
