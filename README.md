# Sentinel — Web Vulnerability Scanner

Flask dashboard that scans any public target: security headers, TLS, open ports, tech fingerprinting — with a live exposure score.

## Architecture

```
URL submitted
      │
      ▼
 ┌──────────┐
 │ Flask API │  app.py
 └─────┬────┘
       │  concurrent.futures
 ┌─────┴──────────────────────────────────┐
 │               scanner.py               │
 ├───────────────┬────────────┬───────────┤
 │   Headers     │   Ports    │  TLS/DNS  │
 │   (9 checks)  │  (15+ TCP) │ cert info │
 └───────────────┴────────────┴───────────┘
       │
       ▼
 Exposure Score 0 → 100
```

## Security headers checked

| Header | Attack blocked |
|--------|----------------|
|  | HTTPS downgrade |
|  | XSS, script injection |
|  | Clickjacking |
|  | MIME sniffing |
|  | Sensitive URL leakage |
|  | Unauthorized camera/mic access |
|  | Timing attacks |
|  | Cross-origin data extraction |
|  | Spectre covert channel |

## Ports scanned

| Severity | Ports |
|----------|-------|
| Critical | 23 Telnet · 445 SMB · 1433 MSSQL · 3306 MySQL · 2375 Docker |
| High | 21 FTP · 2181 Zookeeper · 3000 Grafana |
| Medium | 22 SSH · 25 SMTP · 53 DNS · 110 POP3 · 143 IMAP |
| Info | 80 HTTP · 443 HTTPS |

Also checks: TLS certificate validity and expiry, tech fingerprinting.

## Stack

- **Backend:** Python · Flask ·  ·  ·  ·  · 
- **Frontend:** HTML / CSS / JS vanilla — SOC dashboard aesthetic (IBM Plex Mono + Inter)

## Run

```bash
python3 -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python3 app.py
```

Open 

## File structure

```
├── app.py           # Flask routes
├── scanner.py       # Scan engine (headers, SSL, ports, fingerprint)
├── templates/
│   └── index.html   # Dashboard UI
├── static/
│   ├── style.css
│   └── script.js
└── requirements.txt
```

## Legal

Only scan hosts you own or have explicit authorization to test.

---

Soufiane Filali · Holberton School France
