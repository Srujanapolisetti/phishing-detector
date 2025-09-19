# Phishing Website Detector (Simple heuristics)

This small project contains a Python script that detects suspicious URLs based on simple heuristics:

- IP-based URLs (e.g., http://192.168.0.1/...)
- Too many hyphens in the domain
- Presence of '@' in URL
- Long URL length
- Suspicious keywords in path/query (login, verify, secure, account, update, bank, webscr, signin)
- Misspelled popular domains (uses difflib to check similarity to well-known brands)
- Uses HTTP (not HTTPS) — lower trust (informational)

## Files
- `detect_phishing.py` — main script. Run from command line.
- `example_urls.txt` — sample URLs (benign + phishing) for testing.
- `requirements.txt` — empty (uses Python standard library).

## Usage
```bash
python detect_phishing.py --input example_urls.txt --output results.csv
```

The script writes `results.csv` with columns: url,score,label,reason

Score range: 0.0 (benign) to 1.0 (very suspicious). Label is 'phishing' if score >= 0.5.

## Notes / Limitations
- This is a simple heuristic demo for educational use only. It is NOT a replacement for production-grade phishing detection systems.
- Consider adding more signals (WHOIS age, TLS certificate checks, hosting reputation, page content analysis) for better accuracy.
