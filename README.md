# Sentinel — Web Vulnerability Scanner

A Flask-based web dashboard for external exposure scanning: security headers, TLS certificate health, common open ports, and technology fingerprinting — with a live exposure score.

## Stack

- **Backend:** Python, Flask, `requests`, `ssl`, `socket`
- **Frontend:** vanilla HTML/CSS/JS, no framework — SOC-dashboard aesthetic (IBM Plex Mono + Inter)

## Structure

```
cyber-scanner-web/
├── app.py              # Flask routes
├── scanner.py          # Scan engine (headers, SSL, ports, tech)
├── templates/
│   └── index.html
├── static/
│   ├── style.css
│   └── script.js
└── requirements.txt
```

## Run it

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open `http://127.0.0.1:5000`.

## Legal notice

Only scan hosts you own or are explicitly authorized to test.

## Author

Soufiane Filali — [Souf-F](https://github.com/Souf-F)
