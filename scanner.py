"""Core scanning logic for Sentinel — web vulnerability analyzer."""

import concurrent.futures
import re
import socket
import ssl
from datetime import datetime, timezone
from urllib.parse import urlparse

import dns.resolver
import requests

SECURITY_HEADERS = {
    "Strict-Transport-Security": {
        "desc": "Force le navigateur à utiliser HTTPS.",
        "risk": "Downgrade attack — interception du trafic HTTP en clair sur le même réseau.",
        "fix": "response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'",
    },
    "Content-Security-Policy": {
        "desc": "Restreint les sources autorisées pour scripts, styles et images.",
        "risk": "Faille XSS exploitable — exécution de scripts arbitraires, vol de session.",
        "fix": "response.headers['Content-Security-Policy'] = \"default-src 'self'\"",
    },
    "X-Frame-Options": {
        "desc": "Empêche l'intégration de la page dans une iframe.",
        "risk": "Clickjacking — page piégée dans une iframe invisible pour tromper l'utilisateur.",
        "fix": "response.headers['X-Frame-Options'] = 'DENY'",
    },
    "X-Content-Type-Options": {
        "desc": "Empêche le navigateur de deviner le type MIME.",
        "risk": "MIME sniffing — fichier malveillant déguisé en image peut être exécuté.",
        "fix": "response.headers['X-Content-Type-Options'] = 'nosniff'",
    },
    "Referrer-Policy": {
        "desc": "Contrôle les informations transmises lors de la navigation sortante.",
        "risk": "Fuite d'URLs sensibles (tokens, IDs) vers des sites tiers via le Referer.",
        "fix": "response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'",
    },
    "Permissions-Policy": {
        "desc": "Restreint l'accès aux API du navigateur (caméra, géolocalisation...).",
        "risk": "Script tiers compromis pouvant accéder silencieusement à la caméra ou au micro.",
        "fix": "response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'",
    },
    "Cross-Origin-Opener-Policy": {
        "desc": "Isole le contexte de navigation des fenêtres cross-origin.",
        "risk": "Attaques timing/Spectre via popup cross-origin malveillante.",
        "fix": "response.headers['Cross-Origin-Opener-Policy'] = 'same-origin'",
    },
    "Cross-Origin-Resource-Policy": {
        "desc": "Restreint le chargement des ressources aux origines autorisées.",
        "risk": "Site tiers peut charger vos ressources et en extraire des données sensibles.",
        "fix": "response.headers['Cross-Origin-Resource-Policy'] = 'same-origin'",
    },
    "Cross-Origin-Embedder-Policy": {
        "desc": "Empêche le chargement de ressources cross-origin non explicitement autorisées.",
        "risk": "Canal couvert pour exfiltration de données (attaque Spectre).",
        "fix": "response.headers['Cross-Origin-Embedder-Policy'] = 'require-corp'",
    },
}

COMMON_PORTS = {
    21: ("FTP", "high"),
    22: ("SSH", "medium"),
    23: ("Telnet", "critical"),
    25: ("SMTP", "medium"),
    53: ("DNS", "medium"),
    80: ("HTTP", "info"),
    110: ("POP3", "medium"),
    143: ("IMAP", "medium"),
    443: ("HTTPS", "info"),
    445: ("SMB", "critical"),
    1433: ("MSSQL", "critical"),
    2375: ("Docker Daemon",      "critical"),
    2181: ("Zookeeper",          "high"),
    3000: ("Grafana",            "high"),
    3306: ("MySQL",              "critical"),
    3389: ("RDP",                "critical"),
    5432: ("PostgreSQL",         "critical"),
    5601: ("Kibana",             "high"),
    5900: ("VNC",                "critical"),
    5984: ("CouchDB",            "critical"),
    6379: ("Redis",              "critical"),
    8080: ("HTTP-Alt",           "info"),
    8443: ("HTTPS-Alt",          "info"),
    8888: ("Jupyter Notebook",   "critical"),
    9000: ("Portainer/SonarQube","high"),
    9090: ("Prometheus",         "medium"),
    9200: ("Elasticsearch",      "critical"),
    11211: ("Memcached",         "critical"),
    15672: ("RabbitMQ Mgmt",     "high"),
    27017: ("MongoDB",           "critical"),
}

PORT_DEDUCTION = {"critical": 15, "high": 10, "medium": 5, "info": 0}

TECH_PATTERNS = {
    r"wp-content|wp-includes|wp-json": "WordPress",
    r"drupal\.settings|drupal\.js": "Drupal",
    r"joomla": "Joomla",
    r"magento": "Magento",
    r"shopify": "Shopify",
    r"typo3": "TYPO3",
    r"wix\.com": "Wix",
    r"squarespace\.com": "Squarespace",
    r"__NEXT_DATA__": "Next.js",
    r"ng-version": "Angular",
    r"data-vue-": "Vue.js",
    r'"react"|\breact\.js\b': "React",
    r"svelte": "Svelte",
    r"nuxt": "Nuxt.js",
    r"gatsby": "Gatsby",
    r"laravel_session": "Laravel",
    r"csrfmiddlewaretoken": "Django",
    r"__viewstate|asp\.net": "ASP.NET",
    r"bootstrap": "Bootstrap",
    r"jquery": "jQuery",
    r"tailwind": "Tailwind CSS",
    r"google-analytics\.com|gtag\(": "Google Analytics",
    r"googletagmanager\.com": "Google Tag Manager",
    r"hotjar\.com": "Hotjar",
    r"cloudfront\.net": "Amazon CloudFront",
    r"fastly\.net": "Fastly",
}

WAF_SIGNATURES = {
    "Cloudflare": {
        "headers": ["CF-Ray", "CF-Cache-Status"],
        "server": ["cloudflare"],
        "cookies": ["__cflb", "__cfuid", "cf_clearance"],
    },
    "AWS CloudFront / WAF": {
        "headers": ["X-AMZ-CF-ID", "X-Cache"],
        "server": ["amazons3", "cloudfront"],
        "cookies": [],
    },
    "Akamai": {
        "headers": ["X-Check-Cacheable", "Akamai-Cache-Status"],
        "server": ["akamai"],
        "cookies": ["ak_bmsc"],
    },
    "Imperva / Incapsula": {
        "headers": ["X-Iinfo"],
        "server": ["incapsula"],
        "cookies": ["incap_ses", "visid_incap"],
    },
    "ModSecurity": {
        "headers": [],
        "server": ["mod_security", "modsecurity"],
        "cookies": [],
    },
    "Sucuri": {
        "headers": ["X-Sucuri-ID", "X-Sucuri-Cache"],
        "server": ["sucuri"],
        "cookies": [],
    },
    "F5 BIG-IP": {
        "headers": ["X-WA-Info"],
        "server": ["bigip", "big-ip"],
        "cookies": ["bigipserver"],
    },
    "Fastly": {
        "headers": ["X-Fastly-Request-ID"],
        "server": ["fastly"],
        "cookies": [],
    },
}

SENSITIVE_PATHS = [
    ("/.git/HEAD",            "Répertoire Git exposé",                    "critical"),
    ("/.git/config",          "Config Git (remote + tokens potentiels)",  "critical"),
    ("/.env",                 "Fichier .env exposé",                      "critical"),
    ("/.env.local",           "Fichier .env.local exposé",                "critical"),
    ("/.env.production",      "Fichier .env.production exposé",           "critical"),
    ("/actuator/env",         "Spring Boot Actuator /env (variables !)",  "critical"),
    ("/backup.zip",           "Archive backup exposée",                   "high"),
    ("/backup.sql",           "Dump SQL exposé",                          "high"),
    ("/db.sql",               "Dump SQL exposé",                          "high"),
    ("/phpinfo.php",          "phpinfo() exposé",                         "high"),
    ("/.htpasswd",            "Fichier .htpasswd exposé",                 "critical"),
    ("/wp-config.php.bak",    "Config WordPress backup exposé",           "high"),
    ("/config.php.bak",       "Config PHP backup exposé",                 "high"),
    ("/wp-json/wp/v2/users",  "Énumération utilisateurs WordPress",       "high"),
    ("/phpmyadmin",           "Interface phpMyAdmin accessible",          "high"),
    ("/pma",                  "Interface phpMyAdmin (alias /pma)",        "high"),
    ("/server-status",        "Apache mod_status (connexions actives)",   "high"),
    ("/actuator",             "Spring Boot Actuator dashboard",           "high"),
    ("/elmah.axd",            "ELMAH journal d'erreurs ASP.NET",          "high"),
    ("/xmlrpc.php",           "XML-RPC WordPress (brute-force)",          "medium"),
    ("/Dockerfile",           "Dockerfile exposé",                        "high"),
    ("/docker-compose.yml",   "Docker Compose exposé",                    "high"),
    ("/.DS_Store",            "Fichier .DS_Store macOS (arborescence)",   "medium"),
    ("/package.json",         "package.json Node.js exposé",              "medium"),
    ("/crossdomain.xml",      "crossdomain.xml (politique Flash/legacy)", "medium"),
    ("/graphql",              "Endpoint GraphQL exposé",                  "medium"),
    ("/.ssh/id_rsa",          "Clé SSH privée exposée",                   "critical"),
    ("/.netrc",               ".netrc exposé (identifiants FTP/HTTP)",    "critical"),
    ("/.npmrc",               ".npmrc exposé (tokens npm/registre)",      "critical"),
    ("/credentials.json",     "Google Service Account credentials",       "critical"),
    ("/.bash_history",        "Historique bash exposé",                   "critical"),
    ("/WEB-INF/web.xml",      "Config Java/Tomcat web.xml",               "high"),
    ("/access.log",           "Journal d'accès HTTP exposé",              "high"),
    ("/error.log",            "Journal d'erreurs exposé",                 "high"),
    ("/config.yml",           "Fichier config.yml exposé",                "high"),
    ("/config.yaml",          "Fichier config.yaml exposé",               "high"),
    ("/debug.php",            "Script de debug PHP exposé",               "high"),
    ("/test.php",             "Script de test PHP exposé",                "medium"),
    ("/api/swagger-ui.html",  "Swagger UI accessible",                    "medium"),
    ("/.idea/workspace.xml",  "IDE JetBrains exposé",                     "medium"),
    ("/CHANGELOG.md",         "Changelog exposé (versions logiciel)",     "low"),
    ("/robots.txt",           "Fichier robots.txt",                       "info"),
    ("/.well-known/security.txt", "Security policy présente",            "info"),
    ("/admin",                "Interface admin détectée",                 "medium"),
    ("/administrator",        "Interface admin détectée",                 "medium"),
    ("/swagger.json",         "Documentation Swagger exposée",            "medium"),
    ("/openapi.json",         "Documentation OpenAPI exposée",            "medium"),
    ("/api/v1",               "API endpoint découvert",                   "info"),
]

DISCLOSURE_DEDUCTION = {"critical": 25, "high": 15, "medium": 5, "info": 0}

# For ambiguous paths (valid as URL routes on many platforms), require at least one token
# in the HTTP 200 response to confirm it's a real finding vs a soft-route false positive.
PATH_VERIFY_TOKENS: dict[str, list[str]] = {
    '/phpmyadmin':           ['pmaAbsoluteUri', 'token" name="token"', 'phpmyadmin.css', 'PMA_CommonParams'],
    '/pma':                  ['pmaAbsoluteUri', 'token" name="token"', 'phpmyadmin.css'],
    '/server-status':        ['Apache Server Status', 'requests currently being processed', 'Scoreboard Key'],
    '/Dockerfile':           ['FROM ', 'RUN ', 'CMD ', 'ENTRYPOINT '],
    '/docker-compose.yml':   ['services:', '  image:', '  ports:'],
    '/actuator':             ['"_links":{"self"', '"templated":false', '"templated": false'],
    '/actuator/env':         ['activeProfiles', 'systemProperties', 'propertySources'],
    '/graphql':              ['"data"', '"errors"', '"__schema"'],
    '/elmah.axd':            ['Error Log', 'ELMAH', 'Unhandled Exception'],
    '/xmlrpc.php':           ['<?xml', 'methodResponse', 'faultCode'],
    '/wp-json/wp/v2/users':  ['"slug":', '"link":', '"avatar_urls"'],
    '/package.json':         ['"scripts":', '"dependencies":', '"devDependencies":'],
    '/administrator':        ['task=user.login', 'com_users', 'Joomla! Administration'],
    '/swagger.json':         ['"swagger"', '"openapi"', '"paths"'],
    '/openapi.json':         ['"openapi"', '"paths"', '"info"'],
    '/access.log':           ['GET /', 'POST /', 'HTTP/1.', ' 200 ', ' 404 '],
    '/error.log':            ['PHP Fatal', 'PHP Warning', 'error:', 'Exception', 'Traceback'],
    '/config.yml':           ['host:', 'port:', 'database:', 'password:', 'secret:'],
    '/config.yaml':          ['host:', 'port:', 'database:', 'password:', 'secret:'],
    '/WEB-INF/web.xml':      ['<web-app', '<servlet', '<filter'],
    '/debug.php':            ['phpinfo', 'var_dump', '$_SERVER', 'PHP Version'],
    '/test.php':             ['<?php', 'phpinfo', 'test', 'PHP Version'],
    '/credentials.json':     ['"type":', '"client_email":', '"private_key"'],
    '/.idea/workspace.xml':  ['<project', '<component', 'IntelliJ', 'JetBrains'],
    '/CHANGELOG.md':         ['## ', '### ', 'Released', 'Version', 'v0.', 'v1.', 'v2.'],
    '/api/swagger-ui.html':  ['swagger-ui', 'SwaggerUI', 'Swagger UI'],
}

API_KEY_PATTERNS = [
    (r"AKIA[0-9A-Z]{16}", "Clé AWS Access Key ID (AKIA...)"),
    (r"sk_live_[0-9a-zA-Z]{24,}", "Clé secrète Stripe live (sk_live_...)"),
    (r"AIza[0-9A-Za-z\-_]{35}", "Clé API Google (AIza...)"),
    (r"ghp_[0-9a-zA-Z]{36}", "GitHub Personal Access Token (ghp_...)"),
    (r"gho_[0-9a-zA-Z]{36}", "GitHub OAuth Token (gho_...)"),
    (r"xox[baprs]-[0-9a-zA-Z\-]{10,48}", "Token Slack (xox...)"),
    (r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----", "Clé privée cryptographique exposée"),
    (r'(?i)api[_\-]?key\s*[=:]\s*["\'][^"\']{16,}["\']', "Clé API dans le code source"),
    (r'(?i)secret[_\-]?key\s*[=:]\s*["\'][^"\']{16,}["\']', "Secret dans le code source"),
    (r'(?i)password\s*[=:]\s*["\'][^"\']{8,}["\']', "Mot de passe dans le code source"),
    (r'SG\.[a-zA-Z0-9_\-]{22}\.[a-zA-Z0-9_\-]{43}', "Clé API SendGrid (SG....)"),
    (r'ya29\.[0-9A-Za-z\-_]{40,}', "OAuth2 Access Token Google (ya29....)"),
    (r'(?i)twilio.{0,15}["\'][0-9a-fA-F]{32}["\']', "Token Twilio potentiel"),
    (r'AC[0-9a-fA-F]{32}', "Twilio Account SID (AC....)"),
    (r'(?i)firebase.{0,20}["\'][A-Za-z0-9_\-]{30,}["\']', "Clé Firebase potentielle"),
]

DEBUG_HEADERS_MAP = {
    "X-Debug-Token": ("Symfony debug mode actif en production. La toolbar expose config, requêtes SQL et toutes les variables.", "critical"),
    "X-Debug-Token-Link": ("Lien Symfony Profiler public. Accès complet aux traces de débogage.", "critical"),
    "X-DebugBar-Link": ("Laravel DebugBar actif en production. Expose requêtes SQL, sessions, variables.", "critical"),
    "X-Application-Context": ("Spring Boot : contexte applicatif exposé publiquement.", "high"),
    "X-OWA-Version": ("Version Outlook Web Access exposée. Ciblable avec des CVEs spécifiques.", "high"),
    "X-AspNet-Version": ("Version ASP.NET exposée. Permet de cibler des CVEs spécifiques.", "medium"),
    "X-AspNetMvc-Version": ("Version ASP.NET MVC exposée.", "medium"),
    "Server-Timing": ("Server-Timing révèle les temps de traitement internes (cache, DB, render). Aide à cartographier l'architecture.", "low"),
    "X-Generator": ("Révèle le générateur CMS et parfois sa version exacte.", "low"),
    "X-Drupal-Cache": ("Révèle l'utilisation de Drupal et l'état de son cache.", "low"),
    "X-Varnish": ("Varnish cache ID exposé. Révèle l'infrastructure de cache interne.", "low"),
    "X-Rack-Cache": ("Rack::Cache Rails actif en production. État du cache exposé.", "low"),
    "X-Runtime": ("Rails Server-Timing. Temps de traitement interne exposé.", "low"),
    "X-Litespeed-Cache": ("LiteSpeed cache headers révèlent l'infrastructure.", "low"),
    "X-Envoy-Upstream-Service-Time": ("Envoy proxy interne exposé. Architecture microservices visible.", "medium"),
    "X-Kong-Upstream-Latency": ("Kong API Gateway interne exposé.", "medium"),
    "X-RateLimit-Limit": ("Configuration rate limiting exposée (mécanisme dévoilé).", "low"),
}


def scan_target(url: str) -> dict:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    parsed = urlparse(url)
    hostname = parsed.hostname
    base_url = f"{parsed.scheme}://{parsed.netloc}"

    score = 100
    report = {"url": url, "hostname": hostname}

    response = None
    try:
        response = requests.get(
            url, timeout=10, allow_redirects=True,
            headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
        )
    except requests.RequestException as exc:
        report["request_error"] = str(exc)

    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as executor:
        fut_ssl = executor.submit(_check_ssl, hostname)
        fut_ports = executor.submit(_scan_ports, hostname)
        fut_dns = executor.submit(_check_dns, hostname)
        fut_disclosure = executor.submit(_check_info_disclosure, base_url)
        fut_methods = executor.submit(_check_methods, url)
        fut_redirect = executor.submit(_check_redirect, hostname)
        fut_cors = executor.submit(_check_cors, url)
        fut_open_redirect = executor.submit(_check_open_redirect, url)
        fut_dir_listing = executor.submit(_check_directory_listing, base_url)
        fut_error_disc = executor.submit(_check_error_page_disclosure, url)

        if response is not None:
            h_data, h_ded = _check_headers(response)
            report["headers"] = h_data
            score -= h_ded
            report["tech"] = _detect_tech(response)
            report["waf"] = _detect_waf(response)
            c_data, c_ded = _check_cookies(response)
            report["cookies"] = c_data
            score -= c_ded
            dh_data, dh_ded = _check_deep_headers(response)
            report["deep_headers"] = dh_data
            score -= dh_ded
            src_data, src_ded = _check_source_analysis(response)
            report["source"] = src_data
            score -= src_ded
        else:
            report["headers"] = {"error": report.get("request_error", "Connexion impossible")}
            report["tech"] = []
            report["waf"] = []
            report["cookies"] = {"list": [], "count": 0}
            report["deep_headers"] = {"issues": [], "debug_headers": [], "hsts": None, "csp_present": False}
            report["source"] = {"leaks": [], "no_sri": [], "suspicious_comments": [], "ip_leak_headers": {}}
            report["directory_listing"] = {"found": []}
            report["error_disclosure"] = {"found": False}

        ssl_data, ssl_ded = fut_ssl.result()
        report["ssl"] = ssl_data
        score -= ssl_ded

        ports_data, ports_ded = fut_ports.result()
        report["ports"] = ports_data
        score -= ports_ded

        dns_data, dns_ded = fut_dns.result()
        report["dns"] = dns_data
        score -= dns_ded

        disc_data, disc_ded = fut_disclosure.result()
        report["disclosure"] = disc_data
        score -= disc_ded

        methods_data, methods_ded = fut_methods.result()
        report["methods"] = methods_data
        score -= methods_ded

        redirect_data, redir_ded = fut_redirect.result()
        report["redirect"] = redirect_data
        score -= redir_ded

        cors_data, cors_ded = fut_cors.result()
        report["cors"] = cors_data
        score -= cors_ded

        or_data, or_ded = fut_open_redirect.result()
        report["open_redirect"] = or_data
        score -= or_ded

        dl_data, dl_ded = fut_dir_listing.result()
        report["directory_listing"] = dl_data
        score -= dl_ded

        ed_data, ed_ded = fut_error_disc.result()
        report["error_disclosure"] = ed_data
        score -= ed_ded

    report["score"] = max(score, 0)
    return report


def _check_headers(response) -> tuple:
    missing = [
        {"name": h, **info}
        for h, info in SECURITY_HEADERS.items()
        if h not in response.headers
    ]
    deduction = len(missing) * 5
    server = response.headers.get("Server", "")
    server_verbose = bool(server) and any(
        v in server.lower() for v in ["apache", "nginx", "iis", "php", "python", "ruby", "express"]
    )
    return {
        "status_code": response.status_code,
        "server": server or "hidden",
        "server_verbose": server_verbose,
        "x_powered_by": response.headers.get("X-Powered-By", ""),
        "present": [h for h in SECURITY_HEADERS if h in response.headers],
        "missing": missing,
    }, deduction


def _check_ssl(hostname: str) -> tuple:
    try:
        ctx = ssl.create_default_context()
        with socket.create_connection((hostname, 443), timeout=8) as sock:
            with ctx.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                protocol = ssock.version()
                cipher = ssock.cipher()
    except Exception as exc:
        return {"error": str(exc)}, 15

    not_after = datetime.strptime(cert["notAfter"], "%b %d %H:%M:%S %Y %Z").replace(tzinfo=timezone.utc)
    days_left = (not_after - datetime.now(timezone.utc)).days
    issuer = dict(x[0] for x in cert.get("issuer", []))

    deduction = 0
    if days_left <= 0:
        deduction += 25
    elif days_left < 30:
        deduction += 10

    weak_protocol = protocol in ("TLSv1", "TLSv1.1", "SSLv3", "SSLv2")
    if weak_protocol:
        deduction += 10

    return {
        "valid": days_left > 0,
        "issuer": issuer.get("organizationName", issuer.get("commonName", "unknown")),
        "expires": not_after.strftime("%Y-%m-%d"),
        "days_left": days_left,
        "protocol": protocol,
        "cipher": cipher[0] if cipher else "unknown",
        "weak_protocol": weak_protocol,
    }, deduction


def _scan_ports(hostname: str) -> tuple:
    try:
        ip = socket.gethostbyname(hostname)
    except socket.gaierror as exc:
        return {"error": str(exc)}, 0

    def probe(port):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.8)
        open_ = s.connect_ex((ip, port)) == 0
        s.close()
        return port, open_

    deduction = 0
    open_ports = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=10) as ex:
        for port, is_open in ex.map(probe, COMMON_PORTS.keys()):
            if is_open:
                service, risk = COMMON_PORTS[port]
                deduction += PORT_DEDUCTION.get(risk, 0)
                open_ports.append({"port": port, "service": service, "risk": risk})

    open_ports.sort(key=lambda x: x["port"])
    return {"ip": ip, "open": open_ports}, deduction


def _check_dns(hostname: str) -> tuple:
    resolver = dns.resolver.Resolver()
    resolver.timeout = 5
    resolver.lifetime = 5

    result = {"spf": None, "dmarc": None, "mx": [], "caa": [], "dnssec": False}
    deduction = 0

    try:
        for rdata in resolver.resolve(hostname, "TXT"):
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=spf1"):
                result["spf"] = txt
                break
    except Exception:
        pass

    try:
        for rdata in resolver.resolve(f"_dmarc.{hostname}", "TXT"):
            txt = b"".join(rdata.strings).decode(errors="ignore")
            if txt.startswith("v=DMARC1"):
                result["dmarc"] = txt
                break
    except Exception:
        pass

    try:
        answers = resolver.resolve(hostname, "MX")
        result["mx"] = [str(r.exchange).rstrip(".") for r in sorted(answers, key=lambda x: x.preference)]
    except Exception:
        pass

    try:
        answers = resolver.resolve(hostname, "CAA")
        result["caa"] = [str(r) for r in answers]
    except Exception:
        pass

    # DNSSEC: check for RRSIG records on the A record
    try:
        resolver.resolve(hostname, "RRSIG")
        result["dnssec"] = True
    except Exception:
        result["dnssec"] = False

    if not result["spf"]:
        deduction += 5
    if not result["dmarc"]:
        deduction += 5
    if not result["caa"]:
        deduction += 3
    if not result["dnssec"]:
        deduction += 2

    return result, deduction


def _check_info_disclosure(base_url: str) -> tuple:
    # Canary: probe a nonexistent path to detect soft-404 behavior (sites that return 200 for all paths)
    soft404_size: int | None = None
    try:
        canary = requests.get(
            base_url + "/_sentinel_canary_x9z8y7_notexist.html",
            timeout=5, allow_redirects=False,
            headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
        )
        if canary.status_code == 200:
            soft404_size = len(canary.content)
    except Exception:
        pass

    def probe(entry):
        path, label, risk = entry
        try:
            r = requests.get(
                base_url + path,
                timeout=5, allow_redirects=False,
                headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
            )
            if r.status_code == 404:
                return None
            if r.status_code in (403, 500):
                return {"path": path, "label": label, "risk": risk, "status": r.status_code, "snippet": ""}
            if r.status_code == 200:
                body_size = len(r.content)
                # Soft-404 filter: skip if very similar size to canary
                if soft404_size is not None:
                    diff_pct = abs(body_size - soft404_size) / max(soft404_size, 1)
                    if diff_pct < 0.10:
                        return None
                # Content verification for ambiguous paths
                tokens = PATH_VERIFY_TOKENS.get(path)
                if tokens:
                    body_text = r.text
                    if not any(tok in body_text for tok in tokens):
                        return None
                snippet = r.text[:200].strip()
                return {"path": path, "label": label, "risk": risk, "status": r.status_code, "snippet": snippet}
        except Exception:
            pass
        return None

    found = []
    deduction = 0
    with concurrent.futures.ThreadPoolExecutor(max_workers=16) as ex:
        for item in ex.map(probe, SENSITIVE_PATHS):
            if item:
                found.append(item)
                deduction += DISCLOSURE_DEDUCTION.get(item["risk"], 0)

    return {"found": found}, deduction


def _check_methods(url: str) -> tuple:
    dangerous = {"TRACE", "TRACK", "PUT", "DELETE"}
    METHOD_DED = {"TRACE": 8, "TRACK": 8, "PUT": 5, "DELETE": 3}
    try:
        r = requests.options(
            url, timeout=5,
            headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
        )
        allow = r.headers.get("Allow", r.headers.get("Access-Control-Allow-Methods", ""))
        methods = [m.strip().upper() for m in allow.split(",") if m.strip()]
        risky = [m for m in methods if m in dangerous]
        deduction = min(sum(METHOD_DED.get(m, 3) for m in risky), 15)
        return {"allowed": methods, "risky": risky, "status": r.status_code}, deduction
    except Exception as exc:
        return {"error": str(exc)}, 0


def _check_redirect(hostname: str) -> tuple:
    try:
        r = requests.get(
            f"http://{hostname}", timeout=5, allow_redirects=False,
            headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
        )
        location = r.headers.get("Location", "")
        to_https = r.status_code in (301, 302, 307, 308) and location.startswith("https://")
        return {
            "http_status": r.status_code,
            "redirects_to_https": to_https,
            "location": location,
        }, 0 if to_https else 10
    except Exception as exc:
        return {"error": str(exc)}, 0


def _check_cors(url: str) -> tuple:
    try:
        r = requests.get(
            url, timeout=5,
            headers={"Origin": "https://evil.com", "User-Agent": "Sentinel/1.0 Security Scanner"},
        )
        acao = r.headers.get("Access-Control-Allow-Origin", "")
        acac = r.headers.get("Access-Control-Allow-Credentials", "").lower()
        acam = r.headers.get("Access-Control-Allow-Methods", "")

        wildcard = acao == "*"
        reflects = acao == "https://evil.com"
        credentials = acac == "true"

        deduction = 0
        issues = []
        if wildcard:
            deduction += 10
            issues.append("Access-Control-Allow-Origin: * (toutes origines autorisées)")
        if reflects:
            deduction += 15
            issues.append("L'origine arbitraire est reflétée (CORS injection)")
        if credentials and (wildcard or reflects):
            deduction += 15
            issues.append("Credentials autorisés avec origine non restreinte (vol de session possible)")

        return {
            "acao": acao or "absent",
            "credentials": credentials,
            "methods": acam,
            "wildcard": wildcard,
            "reflects_origin": reflects,
            "issues": issues,
        }, deduction
    except Exception as exc:
        return {"error": str(exc)}, 0


def _check_cookies(response) -> tuple:
    raw_cookies = []
    try:
        raw = response.raw
        h = raw.headers
        if hasattr(h, "getlist"):
            raw_cookies = h.getlist("Set-Cookie")
        elif hasattr(h, "get_all"):
            raw_cookies = h.get_all("Set-Cookie") or []
    except Exception:
        pass

    if not raw_cookies:
        sc = response.headers.get("Set-Cookie")
        if sc:
            raw_cookies = [sc]

    cookies = []
    deduction = 0
    for raw in raw_cookies:
        parts = [p.strip() for p in raw.split(";")]
        name = parts[0].split("=")[0].strip() if parts else "?"
        flags_lower = {p.lower().split("=")[0].strip() for p in parts[1:]}

        has_httponly = "httponly" in flags_lower
        has_secure = "secure" in flags_lower
        samesite_val = next(
            (p.split("=")[1].strip() for p in parts[1:] if p.strip().lower().startswith("samesite=")),
            None,
        )

        issues = []
        if not has_httponly:
            issues.append("HttpOnly manquant — accessible via JavaScript (vol XSS)")
            deduction += 3
        if not has_secure:
            issues.append("Secure manquant — transmis en clair sur HTTP")
            deduction += 3
        if not samesite_val:
            issues.append("SameSite manquant — vulnérable aux attaques CSRF")
            deduction += 2

        cookies.append({
            "name": name,
            "httponly": has_httponly,
            "secure": has_secure,
            "samesite": samesite_val,
            "issues": issues,
        })

    return {"list": cookies, "count": len(cookies)}, min(deduction, 20)


def _detect_tech(response) -> list:
    found = set()
    for pattern, name in TECH_PATTERNS.items():
        if re.search(pattern, response.text, re.IGNORECASE):
            found.add(name)
    if response.headers.get("X-Powered-By"):
        found.add(response.headers["X-Powered-By"])
    return sorted(found)


def _check_deep_headers(response) -> tuple:
    """Analyse the quality of existing security headers + detect debug/info disclosure headers."""
    issues = []
    deduction = 0

    hsts = response.headers.get("Strict-Transport-Security", "")
    hsts_info = None
    if hsts:
        ma = re.search(r"max-age=(\d+)", hsts)
        max_age = int(ma.group(1)) if ma else 0
        include_sub = "includesubdomains" in hsts.lower()
        preload = "preload" in hsts.lower()
        hsts_info = {"max_age": max_age, "include_subdomains": include_sub, "preload": preload}
        if max_age < 31536000:
            issues.append({
                "type": "hsts_short",
                "title": f"HSTS max-age trop court ({max_age}s)",
                "desc": "HSTS max-age inférieur à 1 an (31 536 000s). Les navigateurs oublient le forçage HTTPS trop vite.",
                "fix": "Strict-Transport-Security: max-age=31536000; includeSubDomains; preload",
                "severity": "medium",
            })
            deduction += 5
        if not include_sub:
            issues.append({
                "type": "hsts_no_sub",
                "title": "HSTS sans includeSubDomains",
                "desc": "Les sous-domaines restent vulnérables aux attaques de downgrade HTTP.",
                "fix": "Ajouter includeSubDomains dans l'en-tête HSTS.",
                "severity": "low",
            })
            deduction += 3
        if not preload:
            issues.append({
                "type": "hsts_no_preload",
                "title": "HSTS sans directive preload",
                "desc": "Le premier accès HTTP reste non protégé (attaque TOFU). Soumettre sur hstspreload.org pour une protection maximale.",
                "fix": "Ajouter 'preload' puis soumettre le domaine sur https://hstspreload.org",
                "severity": "info",
            })

    csp = response.headers.get("Content-Security-Policy", "")
    if csp:
        if "'unsafe-inline'" in csp:
            issues.append({
                "type": "csp_unsafe_inline",
                "title": "CSP contient 'unsafe-inline'",
                "desc": "La directive 'unsafe-inline' neutralise la protection XSS de la CSP. N'importe quel script inline peut s'exécuter.",
                "fix": "Remplacer 'unsafe-inline' par des nonces dynamiques : script-src 'nonce-{RANDOM}'",
                "severity": "high",
            })
            deduction += 10
        if "'unsafe-eval'" in csp:
            issues.append({
                "type": "csp_unsafe_eval",
                "title": "CSP contient 'unsafe-eval'",
                "desc": "La directive 'unsafe-eval' autorise eval() et Function(). Un attaquant peut injecter du code via des données.",
                "fix": "Supprimer 'unsafe-eval'. Refactoriser le code qui utilise eval(), setTimeout(string), new Function(string).",
                "severity": "medium",
            })
            deduction += 7

    debug_found = []
    for hdr, (desc, sev) in DEBUG_HEADERS_MAP.items():
        val = response.headers.get(hdr, "")
        if val:
            debug_found.append({"header": hdr, "value": val, "desc": desc, "severity": sev})
            deduction += 8 if sev in ("critical", "high") else 4 if sev == "medium" else 2

    return {
        "issues": issues,
        "debug_headers": debug_found,
        "hsts": hsts_info,
        "csp_present": bool(csp),
    }, min(deduction, 40)


def _check_source_analysis(response) -> tuple:
    """Scan page source for API key leaks, missing SRI, suspicious comments, internal IP headers."""
    html = response.text
    deduction = 0
    leaks = []

    for pattern, label in API_KEY_PATTERNS:
        matches = re.findall(pattern, html)
        if matches:
            raw = str(matches[0])
            snippet = raw[:4] + "****" + raw[-4:] if len(raw) > 8 else raw
            leaks.append({"type": label, "snippet": snippet})
            deduction += 25

    no_sri = []
    for script_tag in re.findall(r'<script[^>]+src=["\']https?://[^"\']+["\'][^>]*>', html, re.IGNORECASE):
        if "integrity=" not in script_tag.lower():
            m = re.search(r'src=["\']([^"\']+)["\']', script_tag, re.IGNORECASE)
            if m:
                no_sri.append(m.group(1))
    no_sri = no_sri[:8]
    if no_sri:
        deduction += min(len(no_sri) * 3, 12)

    suspicious_comments = []
    comment_patterns = [
        (r'(?i)(password|passwd|pwd)\s*[:=]\s*\S+', "Identifiant dans commentaire HTML"),
        (r'(?i)(todo|fixme|hack)\s*:?\s*.{0,20}(?:auth|login|password|key|secret|vuln)', "Note dev sensible dans commentaire"),
        (r'192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+', "Adresse IP interne dans commentaire"),
        (r'(?i)(?:internal|staging|dev)\s+(?:url|endpoint|api|server|host)', "URL interne/staging dans commentaire"),
    ]
    for comment in re.findall(r"<!--(.*?)-->", html, re.DOTALL):
        c = comment.strip()
        if len(c) < 4:
            continue
        for cpat, clabel in comment_patterns:
            if re.search(cpat, c):
                suspicious_comments.append({"text": c[:150], "label": clabel})
                deduction += 8
                break
    suspicious_comments = suspicious_comments[:5]

    internal_ip_re = re.compile(
        r"(?:192\.168\.\d+\.\d+|10\.\d+\.\d+\.\d+|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+|127\.\d+\.\d+\.\d+)"
    )
    ip_leak_headers = {}
    for hdr in ("X-Forwarded-For", "X-Real-IP", "X-Backend-Server", "X-Upstream", "Via", "X-Served-By"):
        val = response.headers.get(hdr, "")
        if val and internal_ip_re.search(val):
            ip_leak_headers[hdr] = val
            deduction += 5

    return {
        "leaks": leaks,
        "no_sri": no_sri,
        "suspicious_comments": suspicious_comments,
        "ip_leak_headers": ip_leak_headers,
    }, min(deduction, 50)


DIRECTORY_PATHS = [
    '/images/', '/uploads/', '/static/', '/assets/', '/files/',
    '/backup/', '/tmp/', '/logs/', '/data/', '/media/', '/public/',
]

ERROR_DISCLOSURE_PATTERNS = re.compile(
    r'You have an error in your SQL syntax'
    r'|ORA-\d{4,5}:'
    r'|PSQLException'
    r'|MySQL.*syntax'
    r'|Unclosed quotation mark'
    r'|Stack trace:'
    r'|at [a-zA-Z0-9_$.]+\([a-zA-Z0-9_]+\.java:\d+\)'
    r'|Traceback \(most recent call last\)'
    r'|Fatal error:.*on line \d+'
    r'|Exception in thread "main"'
    r'|NullPointerException'
    r'|/var/www/'
    r'|C:\\\\(?:inetpub|xampp|wamp|Users)'
    r'|Rails\.root'
    r'|ActiveRecord::',
    re.IGNORECASE,
)


def _check_directory_listing(base_url: str) -> tuple:
    """Check if web server lists directory contents."""
    listing_tokens = ['Index of /', 'Directory listing for', 'Parent Directory', '<table summary="Directory Listing"']

    def probe(path):
        try:
            r = requests.get(
                base_url + path, timeout=4, allow_redirects=False,
                headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
            )
            if r.status_code == 200 and any(tok in r.text for tok in listing_tokens):
                return path
        except Exception:
            pass
        return None

    found = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=len(DIRECTORY_PATHS)) as ex:
        for result in ex.map(probe, DIRECTORY_PATHS):
            if result:
                found.append(result)

    deduction = min(len(found) * 10, 25)
    return {"found": found}, deduction


def _check_error_page_disclosure(url: str) -> tuple:
    """Probe for verbose error pages that reveal internal info (stack traces, paths, SQL errors)."""
    payloads = ["'", "\"<>", "../../../etc/passwd", "1 OR 1=1"]

    for payload in payloads:
        try:
            sep = "&" if "?" in url else "?"
            r = requests.get(
                f"{url}{sep}q={payload}", timeout=4,
                headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
            )
            if r.status_code in (200, 400, 500):
                m = ERROR_DISCLOSURE_PATTERNS.search(r.text)
                if m:
                    return {"found": True, "type": "Erreur verbale exposée", "pattern": m.group()[:60]}, 12
        except Exception:
            pass

    return {"found": False}, 0


def _check_open_redirect(url: str) -> tuple:
    """Test for open redirect at common query parameters."""
    EVIL = "https://evil-sentinel-test.com"
    PARAMS = ["redirect", "url", "next", "return", "returnUrl", "goto", "dest", "redir"]

    def test_param(param):
        try:
            sep = "&" if "?" in url else "?"
            r = requests.get(
                f"{url}{sep}{param}={EVIL}", timeout=3,
                allow_redirects=False,
                headers={"User-Agent": "Sentinel/1.0 Security Scanner"},
            )
            loc = r.headers.get("Location", "")
            if r.status_code in (301, 302, 307, 308) and EVIL in loc:
                return param
        except Exception:
            pass
        return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=len(PARAMS)) as ex:
        futs = {ex.submit(test_param, p): p for p in PARAMS}
        for fut in concurrent.futures.as_completed(futs):
            result = fut.result()
            if result:
                return {"found": True, "param": result}, 20

    return {"found": False}, 0


def _detect_waf(response) -> list:
    header_keys = {k.lower() for k in response.headers.keys()}
    server = response.headers.get("Server", "").lower()
    cookie_names = {c.name.lower() for c in response.cookies}

    detected = []
    for waf_name, sig in WAF_SIGNATURES.items():
        if (
            any(h.lower() in header_keys for h in sig["headers"])
            or any(s in server for s in sig["server"])
            or any(c.lower() in cookie_names for c in sig["cookies"])
        ):
            detected.append(waf_name)

    return detected
