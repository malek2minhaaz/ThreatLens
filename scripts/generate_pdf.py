#!/usr/bin/env python3
"""
Generate ThreatLens System Design PDF using fpdf2.
Reads the markdown-style documentation and converts to a formatted PDF.
"""

from fpdf import FPDF
import re
from datetime import datetime

class ThreatLensPDF(FPDF):
    def __init__(self):
        super().__init__('P', 'mm', 'A4')
        self.set_auto_page_break(True, 20)
        # Add Unicode fonts from Windows system
        self.add_font('Arial', '', r'C:\Windows\Fonts\arial.ttf', uni=True)
        self.add_font('Arial', 'B', r'C:\Windows\Fonts\arialbd.ttf', uni=True)
        self.add_font('Consolas', '', r'C:\Windows\Fonts\consola.ttf', uni=True)
        self.add_font('Consolas', 'B', r'C:\Windows\Fonts\consolab.ttf', uni=True)

    def header(self):
        if self.page_no() > 1:
            self.set_font('Arial', '', 8)
            self.set_text_color(100,100,100)
            self.cell(0, 5, 'ThreatLens — System Design & Database Development', align='L')
            self.cell(0, 5, f'Page {self.page_no()}', align='R', new_x="LMARGIN", new_y="NEXT")
            self.line(10, 12, 200, 12)
            self.ln(5)

    def footer(self):
        self.set_y(-15)
        self.set_font('Arial', '', 7)
        self.set_text_color(128,128,128)
        self.cell(0, 10, f'Generated {datetime.now().strftime("%Y-%m-%d %H:%M")} | ThreatLens v1.0', align='C')

    def chapter_title(self, title, num=None):
        self.set_font('Arial', 'B', 16)
        self.set_text_color(26, 109, 181)  # ThreatLens blue
        if num:
            self.cell(0, 10, f'{num}. {title}', new_x="LMARGIN", new_y="NEXT")
        else:
            self.cell(0, 10, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(3)
        # Underline
        self.set_draw_color(34, 211, 238)  # cyan
        self.set_line_width(0.5)
        self.line(10, self.get_y(), 200, self.get_y())
        self.ln(5)

    def section_title(self, title):
        self.set_font('Arial', 'B', 12)
        self.set_text_color(34, 34, 34)
        self.cell(0, 8, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(2)

    def subsection_title(self, title):
        self.set_font('Arial', 'B', 10)
        self.set_text_color(60, 60, 60)
        self.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        self.ln(1)

    def body_text(self, text):
        self.set_font('Arial', '', 10)
        self.set_text_color(40, 40, 40)
        self.multi_cell(0, 5.5, text, align='L')
        self.ln(2)

    def code_block(self, text):
        self.set_font('Consolas', '', 8)
        self.set_text_color(60, 60, 60)
        self.set_fill_color(245, 245, 245)
        # Calculate lines
        lines = text.count('\n') + 1
        # Check page break
        if self.get_y() + lines * 4.5 > 270:
            self.add_page()
        self.set_x(15)
        self.multi_cell(180, 4.2, text, fill=True)
        self.ln(3)

    def bullet_point(self, text, indent=10):
        self.set_font('Helvetica', '', 10)
        self.set_text_color(40, 40, 40)
        x = self.get_x()
        self.set_x(x + indent)
        self.cell(5, 5.5, '•')
        self.multi_cell(180 - indent, 5.5, text)
        self.ln(1)

    def table_header(self, cols, widths):
        self.set_font('Arial', 'B', 9)
        self.set_fill_color(26, 109, 181)
        self.set_text_color(255, 255, 255)
        for i, (col, w) in enumerate(zip(cols, widths)):
            self.cell(w, 7, col, border=1, fill=True, align='C')
        self.ln()

    def table_row(self, cells, widths, fill=False):
        self.set_font('Arial', '', 8)
        self.set_text_color(40, 40, 40)
        if fill:
            self.set_fill_color(240, 245, 250)
        else:
            self.set_fill_color(255, 255, 255)
        for cell, w in zip(cells, widths):
            self.cell(w, 6, str(cell)[:30], border=1, fill=True, align='L')
        self.ln()


def generate_pdf():
    pdf = ThreatLensPDF()
    pdf.add_page()

    # ===== TITLE PAGE =====
    pdf.ln(30)
    pdf.set_font('Helvetica', 'B', 28)
    pdf.set_text_color(26, 109, 181)
    pdf.cell(0, 15, 'ThreatLens', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.set_font('Helvetica', '', 16)
    pdf.set_text_color(60, 60, 60)
    pdf.cell(0, 10, 'System Design & Database Development', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.set_draw_color(34, 211, 238)
    pdf.set_line_width(0.8)
    pdf.line(60, pdf.get_y(), 150, pdf.get_y())
    pdf.ln(10)
    pdf.set_font('Helvetica', '', 12)
    pdf.set_text_color(100, 100, 100)
    pdf.cell(0, 8, 'Threat Detection & URL Scanner Platform', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.cell(0, 8, 'Version 1.0.0', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(5)
    pdf.cell(0, 8, f'Document Generated: {datetime.now().strftime("%B %d, %Y")}', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)
    pdf.set_font('Helvetica', '', 10)
    pdf.cell(0, 6, 'Technologies: FastAPI · SQLite · SQLAlchemy · HTML/CSS/JS · Chrome Extension', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(20)

    # TOC placeholder
    pdf.set_font('Helvetica', 'B', 14)
    pdf.set_text_color(26, 109, 181)
    pdf.cell(0, 10, 'Table of Contents', align='C', new_x="LMARGIN", new_y="NEXT")
    pdf.ln(10)
    pdf.set_font('Helvetica', '', 11)
    pdf.set_text_color(40, 40, 40)
    toc_items = [
        ("6.", "System Design & Database Development"),
        ("7.", "UML Diagrams"),
        ("   7.1", "Use Case Diagram"),
        ("   7.2", "Class Diagram"),
        ("   7.3", "Activity Diagram"),
        ("8.", "Data Dictionary"),
        ("9.", "Finalized Database Schema"),
    ]
    for num, title in toc_items:
        pdf.cell(20, 7, num, align='R')
        pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")

    # ===== SECTION 6: SYSTEM DESIGN =====
    pdf.add_page()
    pdf.chapter_title('System Design & Database Development', '6')

    pdf.section_title('6.1 System Architecture Overview')
    pdf.body_text('ThreatLens is a comprehensive threat detection platform consisting of three main components: a frontend dashboard (HTML/CSS/JS), a backend API server (FastAPI + SQLite), and a Chrome browser extension. The system integrates with external threat intelligence providers including VirusTotal, Google Safe Browsing, and PhishTank to deliver comprehensive URL and content security analysis.')

    pdf.ln(3)
    pdf.subsection_title('Architecture Diagram')
    pdf.code_block("""
    ┌─────────────────────────────────────────────────────────────────┐
    │                        THREATLENS SYSTEM                        │
    ├─────────────────────────────────────────────────────────────────┤
    │                                                                  │
    │  ┌──────────────┐     ┌──────────────┐     ┌──────────────┐   │
    │  │   Frontend   │     │   Backend    │     │  Extension   │   │
    │  │  (HTML/CSS/  │◄───►│  (FastAPI +  │     │  (Chrome     │   │
    │  │     JS)      │     │   SQLite)    │     │   Extension) │   │
    │  └──────────────┘     └──────────────┘     └──────────────┘   │
    │         │                     │                     │          │
    │         ▼                     ▼                     ▼          │
    │  ┌─────────────────────────────────────────────────────────┐   │
    │  │                  SQLite Database                         │   │
    │  │  (threatshield.db)                                       │   │
    │  └─────────────────────────────────────────────────────────┘   │
    │                                                                  │
    │  ┌─────────────────────────────────────────────────────────┐   │
    │  │            External Threat Intelligence                  │   │
    │  │  ┌──────────┐  ┌──────────────────┐  ┌──────────┐     │   │
    │  │  │VirusTotal│  │Google Safe       │  │PhishTank │     │   │
    │  │  │   API    │  │Browsing API      │  │   API    │     │   │
    │  │  └──────────┘  └──────────────────┘  └──────────┘     │   │
    │  └─────────────────────────────────────────────────────────┘   │
    └─────────────────────────────────────────────────────────────────┘
    """)

    pdf.section_title('6.2 Technology Stack')
    pdf.table_header(['Layer', 'Technology'], [50, 140])
    pdf.table_row(['Backend Framework', 'FastAPI (Python 3.11+)'], [50, 140], True)
    pdf.table_row(['Database', 'SQLite (via SQLAlchemy ORM)'], [50, 140])
    pdf.table_row(['Authentication', 'DB-backed bearer tokens (PBKDF2-HMAC-SHA256)'], [50, 140], True)
    pdf.table_row(['Frontend', 'Vanilla HTML5, CSS3, JavaScript (ES6+)'], [50, 140])
    pdf.table_row(['External APIs', 'VirusTotal v3, Google Safe Browsing v4, PhishTank'], [50, 140], True)
    pdf.table_row(['Extension', 'Chrome Extension Manifest V3'], [50, 140])
    pdf.table_row(['Rate Limiting', 'In-memory sliding window (per-process)'], [50, 140], True)

    pdf.ln(5)
    pdf.section_title('6.3 Backend Service Architecture')
    pdf.code_block("""
    ROUTERS (API Endpoints):
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │  auth    │ │ scanner  │ │phishing  │ │  admin   │
    │/api/auth │ │/api/scan │ │/api/phish│ │/api/admin│
    └──────────┘ └──────────┘ └──────────┘ └──────────┘
    ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐
    │  users   │ │ history  │ │  intel   │ │ webhooks │
    │/api/users│ │/api/hist │ │/api/intel│ │/api/web  │
    └──────────┘ └──────────┘ └──────────┘ └──────────┘
    ┌──────────┐ ┌──────────┐
    │  audit   │ │  tools   │
    │/api/audit│ │/api/tool │
    └──────────┘ └──────────┘

    SERVICES (Business Logic):
    scanner.py      → Orchestrates full scan pipeline
    heuristics.py   → Typosquatting, TLD, entropy, structure checks
    metadata.py     → WHOIS, SSL, HTTP inspection
    threat_intel.py → VirusTotal, Safe Browsing, PhishTank
    risk_scoring.py → Unified 0-100 risk scoring engine
    url_parser.py   → URL normalization & parsing
    phishing_analyzer.py → Rule-based NLP phishing detection
    watchlist.py    → User watchlist matching
    security.py     → Password hashing, token generation
    rate_limit.py   → Sliding window rate limiting
    """)

    pdf.section_title('6.4 URL Scan Pipeline Flow')
    pdf.code_block("""
    INPUT: Raw URL
       │
       ▼
    STEP 1: PARSE & NORMALIZE
       - Add http:// if missing
       - Extract: scheme, host, port, path, query
       - Detect IP addresses (v4/v6)
       - Extract: SLD, TLD, registrable domain
       - Validate: only http/https allowed

       ▼
    STEP 2: HEURISTIC ANALYSIS (offline, instant)
       - Typosquatting detection (Levenshtein distance)
       - Suspicious TLD check (.tk, .ml, .xyz, etc.)
       - High entropy / randomized domain detection
       - Structural checks: IP in URL, '@' deception,
         non-standard port, no HTTPS, excessive subdomains,
         URL shorteners, Punycode/IDN, credential paths

       ▼
    STEP 3: METADATA INSPECTION (parallel via thread pool)
       ┌──────────┬──────────┬──────────┐
       │  WHOIS   │   SSL    │   HTTP   │
       │ - Age    │ - Issuer │ - Status │
       │ - Registrar│ - Valid │ - Headers│
       │ - NS     │ - Days   │ - Chain  │
       │ - Status │   left   │ - Redirect│
       └──────────┴──────────┴──────────┘
       SSRF Protection: Block internal IPs

       ▼
    STEP 4: THREAT INTELLIGENCE (optional, skip if no API keys)
       - VirusTotal: Multi-engine AV scan + polling
       - Google Safe Browsing: Threat list query
       - PhishTank: Community phishing database check

       ▼
    STEP 5: RISK SCORING
       - Start: score = 100 (safe)
       - Apply finding points (+/-) from all steps
       - Clamp: 0-100
       - Classify:
         ≥85 → SAFE (green)
         ≥70 → LOW RISK (yellow-green)
         ≥40 → SUSPICIOUS (amber)
         <40 → DANGEROUS (red)

       ▼
    OUTPUT: JSON Risk Report
    - risk_score, verdict, risk_level
    - findings[], category_totals{}
    - metadata{whois, ssl, http}
    - threat_intel{vt, gsb, pt}
    - duration_ms, scanned_at
    """)

    # ===== SECTION 7: UML DIAGRAMS =====
    pdf.add_page()
    pdf.chapter_title('UML Diagrams', '7')

    pdf.section_title('7.1 Use Case Diagram')
    pdf.body_text('The Use Case Diagram illustrates the interactions between different user types (Guest, User, Admin) and the system functionalities.')

    pdf.code_block("""
    ACTORS:
    ┌──────────────┐        ┌──────────────┐        ┌──────────────┐
    │   Guest      │        │   User       │        │   Admin       │
    │  (Unauth.)   │        │ (Authenticated)│       │               │
    └──────┬───────┘        └──────┬───────┘        └──────┬───────┘
           │                       │                       │
           ▼                       ▼                       ▼

    USER ACTIVITIES:
    ┌─────────────────────────────────────────────────────────────────┐
    │  • Register Account                                             │
    │  • Scan URL (Single/Bulk)                                       │
    │  • Run Full Scan Pipeline (Parse → Heuristics → Metadata →      │
    │    Threat Intel → Risk Scoring)                                 │
    │  • View Scan Results (Score, Verdict, Findings, Breakdown)      │
    │  • Analyze Phishing Content                                     │
    │  • Use Phishing Tools (Link Inspector, Email Headers,          │
    │    Sender Check, Watchlist)                                     │
    │  • View History (Scans/Phishing Analyses)                       │
    │  • Search/Filter History (By Verdict, Date, Risk Level)         │
    │  • Download Report (HTML/CSV/JSON)                              │
    └─────────────────────────────────────────────────────────────────┘

    ADMIN ACTIVITIES (Admin Only):
    ┌─────────────────────────────────────────────────────────────────┐
    │  • View Platform Stats (Users, Scans, Detection Rate, etc.)     │
    │  • List All Users                                               │
    │  • Promote/Demote Users                                         │
    │  • Delete Users                                                 │
    │  • View All Scans (Across All Users)                            │
    │  • View Audit Log                                               │
    │  • Monitor Threat Intel Providers                               │
    └─────────────────────────────────────────────────────────────────┘

    EXTERNAL SYSTEMS:
    ┌──────────────┐  ┌──────────────────┐  ┌──────────────┐
    │  VirusTotal  │  │ Google Safe      │  │  PhishTank   │
    │    API       │  │ Browsing API     │  │    API       │
    └──────────────┘  └──────────────────┘  └──────────────┘
    """)

    pdf.add_page()
    pdf.section_title('7.2 Class Diagram')
    pdf.body_text('The Class Diagram shows the database entities (SQLAlchemy ORM models), service classes, frontend modules, and Chrome extension components with their relationships.')

    pdf.subsection_title('Entity Classes (SQLAlchemy Models)')
    pdf.code_block("""
    ┌──────────────────────┐       ┌──────────────────────┐
    │        User          │       │     AuthToken        │
    ├──────────────────────┤       ├──────────────────────┤
    │ - id: int (PK)       │       │ - id: int (PK)       │
    │ - username: string   │◄──┐  │ - token: string      │
    │   (24, unique)       │  │  │   (64, unique)       │
    │ - email: string      │  │  │ - user_id: int (FK)  │
    │   (254, unique)      │  │  │   → User.id          │
    │ - password_hash: str │  │  │ - created_at: datetime│
    │   (255)              │  │  │ - expires_at: datetime│
    │ - display_name: str  │  │  │                      │
    │   (50, nullable)     │  │  └──────────────────────┘
    │ - is_admin: boolean  │  │              │
    │   (default False)    │  │              │ 1:N
    │ - created_at: dt     │  │              │
    ├──────────────────────┤  │              ▼
    │ + public_name: str   │  │    ┌──────────────────────┐
    └──────────────────────┘  │    │    ScanRecord        │
           ▲                 │    ├──────────────────────┤
           │ 1:N             │    │ - id: int (PK)       │
           │                 │    │ - user_id: int (FK)  │
           │                 │    │   → User.id (SET NULL)│
           │                 │    │ - url: string (2048) │
           │                 │    │ - risk_score: int    │
           │                 │    │ - verdict: string(50)│
           │                 │    │ - summary: text (JSON)│
           │                 │    │ - findings: text (JSON)│
           │                 │    │ - created_at: datetime│
           │                 │    └──────────────────────┘
           │                 │              │
           │                 │              │ 1:N
           │                 │              ▼
           │                 │    ┌──────────────────────┐
           │                 │    │  PhishingAnalysis    │
           │                 │    ├──────────────────────┤
           │                 │    │ - id: int (PK)       │
           │                 │    │ - user_id: int (FK)  │
           │                 │    │   → User.id (SET NULL)│
           │                 │    │ - content_type: str  │
           │                 │    │   (50, default"email")│
           │                 │    │ - content_preview:   │
           │                 │    │   string (500)       │
           │                 │    │ - phishing_score: int│
           │                 │    │ - verdict: string(50)│
           │                 │    │ - flags: text (JSON) │
           │                 │    │ - created_at: datetime│
           │                 │    └──────────────────────┘

    ADDITIONAL ENTITIES:
    ┌──────────────────────┐  ┌──────────────────────┐
    │   WatchlistEntry     │  │     AuditLog         │
    ├──────────────────────┤  ├──────────────────────┤
    │ - id: int (PK)       │  │ - id: int (PK)       │
    │ - user_id: int (FK)  │  │ - user_id: int (FK)  │
    │   → User.id          │  │   → User.id          │
    │ - kind: string(10)   │  │ - action: string(100)│
    │   (sender|domain|url)│  │ - detail: text       │
    │ - value: string(2048)│  │   (nullable)         │
    │ - note: string(200)  │  │ - ip_address: string │
    │   (nullable)         │  │   (45, nullable)     │
    │ - created_at: dt     │  │ - created_at: dt     │
    │ - last_seen_at: dt   │  └──────────────────────┘
    │   (nullable)         │           │ 1:N
    └──────────────────────┘           ▼
    ┌──────────────────────┐  ┌──────────────────────┐
    │       APIKey         │  │       Webhook        │
    ├──────────────────────┤  ├──────────────────────┤
    │ - id: int (PK)       │  │ - id: int (PK)       │
    │ - user_id: int (FK)  │  │ - user_id: int (FK)  │
    │   → User.id          │  │   → User.id          │
    │ - key_hash: string   │  │ - url: string(2048)  │
    │   (128, unique)      │  │ - secret: string(64) │
    │ - name: string(100)  │  │ - events: text (JSON)│
    │ - prefix: string(8)  │  │ - is_active: boolean │
    │ - is_active: boolean │  │ - last_triggered_at: │
    │ - last_used_at: dt   │  │   datetime (nullable)│
    │ - created_at: dt     │  │ - created_at: dt     │
    │ - expires_at: dt     │  └──────────────────────┘
    │   (nullable)         │
    └──────────────────────┘

    RELATIONSHIPS:
    users 1 ──┬──► N auth_tokens
              ├──► N scans (ON DELETE SET NULL)
              ├──► N phishing_analyses (ON DELETE SET NULL)
              ├──► N watchlist_entries (ON DELETE CASCADE)
              ├──► N audit_log (ON DELETE SET NULL)
              ├──► N api_keys (ON DELETE CASCADE)
              └──► N webhooks (ON DELETE CASCADE)
    """)

    pdf.add_page()
    pdf.subsection_title('Service & Logic Classes')
    pdf.code_block("""
    SLIDING WINDOW LIMITERS (rate_limit.py):
    ┌──────────────────────┐
    │    SlidingWindow     │
    │      Limiter         │
    ├──────────────────────┤
    │ - max_attempts: int  │
    │ - window_seconds: int│
    │ - _hits: dict        │
    │ - _lock: Lock        │
    ├──────────────────────┤
    │ + allow(key) → bool  │
    │ + reset(key)         │
    └──────────────────────┘
         │ 4 instances
         ▼
    ┌──────────────────────┐
    │    Rate Limiters     │
    │                      │
    │ - login_limiter      │ (10 attempts / 15 min)
    │ - register_limiter   │ (5 attempts / hour)
    │ - tool_limiter       │ (30 attempts / hour)
    │ - scan_limiter       │ (20 scans / hour)
    └──────────────────────┘

    PARSED URL (url_parser.py - Dataclass):
    ┌──────────────────────┐
    │    ParsedUrl         │
    ├──────────────────────┤
    │ - raw: str           │
    │ - normalized: str    │
    │ - scheme: str        │
    │ - host: str          │
    │ - port: int|None     │
    │ - path: str          │
    │ - query: str         │
    │ - fragment: str      │
    │ - is_ip: bool        │
    │ - ip_version: int|None│
    │ - sld: str           │ (second-level domain)
    │ - tld: str           │
    │ - registrable: str   │
    │ - subdomain: str     │
    │ - url_length: int    │
    │ - has_https: bool    │
    │ - default_port: bool │
    ├──────────────────────┤
    │ + to_dict() → dict   │
    └──────────────────────┘

    SCAN ORCHESTRATION (scanner.py):
    ┌──────────────────────┐
    │    scan_url()        │
    │    (async function)  │
    ├──────────────────────┤
    │ INPUT: raw_url: str  │
    ├──────────────────────┤
    │ STEPS:               │
    │ 1. parse_url()       │
    │ 2. run_heuristics()  │
    │ 3. asyncio.gather(   │
    │    fetch_whois(),    │
    │    fetch_ssl(),      │
    │    fetch_http())     │
    │ 4. run_threat_intel()│
    │ 5. compute_risk()    │
    ├──────────────────────┤
    │ OUTPUT: dict with    │
    │ - request, risk_score│
    │ - verdict, findings  │
    │ - metadata, intel    │
    │ - duration_ms        │
    └──────────────────────┘

    RISK SCORING (risk_scoring.py):
    ┌──────────────────────┐
    │   compute_risk()     │
    ├──────────────────────┤
    │ INPUT: findings: list│
    │   of finding dicts   │
    │                      │
    │ PROCESS:             │
    │ - Start score: 100   │
    │ - Apply each finding │
    │   points (+/-)       │
    │ - Clamp 0-100        │
    │ - Classify verdict   │
    │   by threshold       │
    │                      │
    │ OUTPUT: RiskReport   │
    │ - score: int         │
    │ - verdict: string    │
    │ - risk_level: string │
    │ - findings: list     │
    │ - category_totals    │
    └──────────────────────┘

    PHISHING ANALYZER (phishing_analyzer.py):
    ┌──────────────────────┐
    │  analyze_phishing()  │
    ├──────────────────────┤
    │ INPUT: content: str  │
    │       content_type   │
    │   (email|sms|page)   │
    ├──────────────────────┤
    │ PROCESS:             │
    │ - Keyword detection  │
    │   (urgency,threat,   │
    │   financial,cred)    │
    │ - Structural signals │
    │   (greetings,sender, │
    │   links,phone,etc)   │
    │ - Score aggregation  │
    │                      │
    │ OUTPUT: dict with    │
    │ - phishing_score     │
    │ - verdict            │
    │ - confidence         │
    │ - flags: list        │
    │ - matched_keywords   │
    │ - stats              │
    └──────────────────────┘
    """)

    pdf.add_page()
    pdf.subsection_title('Frontend JavaScript Modules')
    pdf.code_block("""
    App (app.js - Singleton IIFE Module):
    ┌──────────────────────┐
    │        App           │
    │   (app.js)           │
    ├──────────────────────┤
    │ STATE:               │
    │ - user: User|null    │
    │                      │
    │ API ENDPOINTS:       │
    │ - API.scan, scanBulk │
    │ - API.auth (login/   │
    │   register/logout/me)│
    │ - API.phishing       │
    │ - API.history        │
    │ - API.intelFeed      │
    │ - API.stats, report  │
    │ - API.watchlist      │
    │ - API.admin          │
    │                      │
    │ UTILITIES:           │
    │ - apiFetch()         │
    │ - toast()            │
    │ - escapeHtml()       │
    │ - verdictClass()     │
    │ - severityClass()    │
    │ - timeAgo()          │
    │ - initials()         │
    │ - animateValue()     │
    │                      │
    │ BOOT FUNCTIONS:      │
    │ - boot()             │
    │ - renderShell()      │
    │ - renderNav()        │
    │ - loadUser()         │
    │ - checkApi()         │
    │ - ensureAdmin()      │
    │ - initTabs()         │
    │ - initKeyboardShort- │
    │   cuts()             │
    │ - registerService-   │
    │   Worker()           │
    └──────────────────────┘

    PAGE MODULES (static/js/pages/):
    ┌──────────────────────┐
    │ scanner.js           │ • runScan() / runBulkScan()
    │ (scanner.html)       │ • renderReport() (gauge, findings)
    │                      │ • Compare mode, CSV import
    ├──────────────────────┤
    │ auth.js              │ • Login form handler
    │ (login/register.html)│ • Register form handler
    │                      │ • Token storage, admin flag
    ├──────────────────────┤
    │ admin.js             │ • loadStats() / loadUsers()
    │ (admin.html)         │ • loadScans() / loadAudit()
    │                      │ • User promote/demote/delete
    ├──────────────────────┤
    │ history.js           │ • loadTab() (scans/phishing)
    │ (history.html)       │ • renderCards() with filtering
    │                      │ • Verdict filter chips
    ├──────────────────────┤
    │ intel.js             │ • loadProviders() / loadFeed()
    │ (intel.html)         │ • Detection filter chips
    │                      │ • Auto-refresh every 60s
    ├──────────────────────┤
    │ learn.js             │ • Example library rendering
    │ (learn.html)         │ • Spot-the-Phish quiz (5 questions)
    ├──────────────────────┤
    │ phishing.js          │ • Content Analyzer tab
    │ (phishing.html)      │ • renderPhishResult() (meter,flags)
    ├──────────────────────┤
    │ phishing-tools.js    │ • Link Inspector
    │                      │ • Email Header Analyzer
    │                      │ • Sender Domain Check
    │                      │ • Watchlist CRUD
    ├──────────────────────┤
    │ profile.js           │ • loadProfile() / loadPhishTrends()
    │ (profile.html)       │ • Report download (HTML/CSV/JSON)
    │                      │ • Profile edit, password change
    └──────────────────────┘

    CHROME EXTENSION (extension/):
    ┌──────────────────────┐       ┌──────────────────────┐
    │     background.js    │       │      shared.js       │
    │  (Service Worker)    │       │   (Utility Module)   │
    ├──────────────────────┤       ├──────────────────────┤
    │ - Context menus:     │       │ - TL.getConfig()     │
    │   • Scan page        │       │ - TL.setConfig()     │
    │   • Scan link        │       │ - TL.api()           │
    │   • Scan selection   │       │ - TL.scan()          │
    │                      │       │ - TL.scoreColor()    │
    │ - Badge management:  │       │ - TL.verdictClass()  │
    │   • set-badge        │       │ - TL.escapeHtml()    │
    │   • clear-badge      │       │ - TL.fmtDuration()   │
    └────────┬─────────────┘       └──────────┬───────────┘
             │                                 │ used by
             │                                 ▼
             │                    ┌──────────────────────┐
             └───────────────────►│      popup.js        │
                                  │ (Toolbar popup)      │
                                  ├──────────────────────┤
                                  │ - Pre-fill URL from  │
                                  │   active tab         │
                                  │ - Scan button        │
                                  │ - render() result    │
                                  └──────────────────────┘
                                  ┌──────────────────────┐
                                  │     options.js       │
                                  │ (Settings page)      │
                                  ├──────────────────────┤
                                  │ - Server URL input   │
                                  │ - Login credentials  │
                                  │ - Sign out           │
                                  └──────────────────────┘
                                  ┌──────────────────────┐
                                  │     results.js       │
                                  │ (Scan results page)  │
                                  ├──────────────────────┤
                                  │ - Full report render │
                                  │ - Rescan, raw JSON   │
                                  │ - Open dashboard     │
                                  └──────────────────────┘
    """)

    pdf.add_page()
    pdf.section_title('7.3 Activity Diagram')
    pdf.body_text('The Activity Diagram shows the step-by-step flow of a URL scan request through the system, including authentication, rate limiting, the scan pipeline stages, and the response rendering.')

    pdf.code_block("""
    URL SCAN ACTIVITY FLOW:

    START: User submits URL scan request
       │
       ▼
    ┌──────────────────────────────────────────────────────┐
    │ AUTHENTICATION CHECK                                 │
    │                                                      │
    │ [App.boot() → isAuthed()?]                           │
    │                                                      │
    │   ┌──────────────┬──────────────┐                    │
    │   │   NO (unAuth)│    YES       │                    │
    │   │              │              │                    │
    │   ▼              ▼              │                    │
    │ ┌──────────┐  ┌────────────────┐│                    │
    │ │ Redirect │  │ Continue to    ││                    │
    │ │ to login │  │ scan endpoint  ││                    │
    │ │ .html    │  │                ││                    │
    │ └──────────┘  └───────┬────────┘│                    │
    │                      │          │                    │
    └──────────────────────┘          │                    │
                                      ▼                    │
                              ┌─────────────┴─────────────┐
                              │ SCAN RATE LIMIT CHECK     │
                              │ (20/hour per user)        │
                              └─────────────┬─────────────┘
                                              │
                    ┌─────────────────────────┴─────────────────────────┐
                    │                                                  │
                    ▼                                                  ▼
              ┌────────────┐                                ┌────────────┐
              │  ALLOWED   │                                │   BLOCKED  │
              │            │                                │  429 Error │
              └─────┬──────┘                                │  + Toast   │
                    │                                        └────────────┘
                    ▼
    ┌───────────────────────────────────────────────────────────────┐
    │                    SCAN PIPELINE                                │
    │                                                                │
    │  STEP 1: PARSE URL                                            │
    │  parse_url(raw_url)                                           │
    │  ├─ Add http:// if missing                                    │
    │  ├─ Extract: scheme, host, port, path, query                  │
    │  ├─ Detect IP address (v4/v6)                                 │
    │  ├─ Extract: SLD, TLD, registrable domain                     │
    │  └─ Validate: only http/https                                 │
    │                                                                │
    │           ┌─────────────┴─────────────┐                      │
    │           │                           │                      │
    │           ▼                           ▼                      │
    │      ┌──────────┐             ┌──────────┐                 │
    │      │  VALID   │             │  INVALID │                 │
    │      │  Parsed  │             │  URL     │                 │
    │      │  URL obj │             │          │                 │
    │      └────┬─────┘             └────┬─────┘                 │
    │           │                          │                      │
    └───────────┼──────────────────────────┼──────────────────────┘
                │                          │
                ▼                          ▼
         ┌──────────────────┐     ┌──────────────┐
         │ Continue Pipeline │     │ Raise        │
         │                   │     │ InvalidURLEr-│
         │                   │     │ ror (400)    │
         └────────┬──────────┘     └──────────────┘
                  │
                  ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  STEP 2: HEURISTIC ANALYSIS (offline, instant)               │
    │  run_heuristics(parsed) → list[findings]                     │
    │                                                                │
    │  Checks:                                                        │
    │  ├─ check_suspicious_tld()  (.tk, .ml, .xyz, etc.)          │
    │  ├─ check_high_entropy()    (randomized domain detection)     │
    │  ├─ check_typosquatting()   (Levenshtein distance to brands)  │
    │  └─ check_structure()        (IP, '@', port, HTTPS, etc.)    │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  STEP 3: METADATA INSPECTION (parallel via thread pool)       │
    │  asyncio.gather(                                               │
    │    fetch_whois(parsed),   ← WHOIS lookup                      │
    │    fetch_ssl(parsed),     ← TLS certificate                   │
    │    fetch_http(parsed),    ← HTTP + redirect chain             │
    │  )                                                             │
    │                                                                │
    │  SSRF Guard: Each function blocks internal IPs                 │
    │  - Block: loopback, private, link-local, multicast            │
    │  - Block: reserved, unspecified addresses                      │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  STEP 4: THREAT INTELLIGENCE (optional providers)             │
    │  run_threat_intel(parsed) → dict                              │
    │                                                                │
    │  VirusTotal:                         Google Safe Browsing:    │
    │  ├─ API key set?                      ├─ API key set?         │
    │  │   YES → Scan URL + poll results    │   YES → Query threat  │
    │  │   NO  → Skip + note                │   NO  → Skip + note   │
    │  └────────────────────────────────────┴───────────────────────┘
    │                                                                │
    │  PhishTank:                                                     │
    │  ├─ API key set?                                                │
    │  │   YES → Check URL in database                                │
    │  │   NO  → Skip + note                                          │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  STEP 5: RISK SCORING                                         │
    │  All findings collected:                                      │
    │  - heuristic_findings (from step 2)                          │
    │  - metadata_findings (from step 3)                           │
    │  - intel_findings (from step 4)                              │
    │                                                                │
    │  compute_risk(all_findings) → RiskReport                     │
    │  - Start: score = 100                                        │
    │  - For each finding: score += points                         │
    │  - Clamp: max(0, min(100, score))                           │
    │  - Classify:                                                  │
    │    ≥85 → SAFE (green)                                       │
    │    ≥70 → LOW RISK (yellow-green)                            │
    │    ≥40 → SUSPICIOUS (amber)                                 │
    │    <40 → DANGEROUS (red)                                    │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  STEP 6: PERSIST TO DATABASE                                  │
    │  INSERT INTO scans (user_id, url, risk_score, verdict,       │
    │                     summary, findings, created_at)            │
    │  VALUES (?, ?, ?, ?, ?, ?, ?)                                │
    │                                                                │
    │  summary = JSON.stringify({                                   │
    │    request, category_totals, metadata,                       │
    │    threat_intel, providers, duration_ms, scanned_at          │
    │  })                                                           │
    │  findings = JSON.stringify(findings_array)                   │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  STEP 7: RETURN RESULT TO USER                                │
    │  Response: {                                                  │
    │    scan_id: int,                                              │
    │    risk_score: int,                                           │
    │    verdict: string,                                           │
    │    risk_level: string,                                        │
    │    findings: [...],                                           │
    │    category_totals: {...},                                    │
    │    metadata: {whois, ssl, http},                             │
    │    threat_intel: {vt, gsb, pt},                              │
    │    duration_ms: int,                                          │
    │    scanned_at: ISO8601                                        │
    │  }                                                            │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  FRONTEND: RENDER REPORT                                       │
    │  renderReport(data) →                                        │
    │  - Animate gauge (SVG circle)                                │
    │  - Display verdict badge                                      │
    │  - Populate stat cards (age, TLS, HTTP, AV, etc.)           │
    │  - Render findings list with severity colors                 │
    │  - Show category breakdown cards                             │
    │  - Populate metadata tab (WHOIS/SSL/HTTP details)            │
    │  - Enable raw JSON view / download                            │
    └─────────────────────────────────┬─────────────────────────────┘
                                      │
                                      ▼
                               END (Report shown)

    ERROR PATHS:
    • Timeout (504): "Scan timed out — the target may be slow"
    • Scan failure: "Scan failed: {exception}"
    • Invalid URL: "Invalid URL: {error message}"
    • Rate limited: "Too many scan requests. Try again later."
    """)

    pdf.add_page()
    pdf.section_title('Phishing Analysis Activity Flow')
    pdf.code_block("""
    PHISHING ANALYSIS ACTIVITY FLOW:

    START: User submits content for analysis
       │
       ▼
    ┌───────────────────────────────────────────────────────────────┐
    │  analyze_phishing(content, content_type)                     │
    │                                                              │
    │  KEYWORD DETECTION                                           │
    │  ┌─────────────────────────────────────────────────────────┐  │
    │  │ URGENCY_KEYWORDS: "urgent", "immediately", "asap", ... │  │
    │  │ → flag: "Urgency pressure" (+20 pts, high)             │  │
    │  │                                                         │  │
    │  │ THREAT_KEYWORDS: "account suspended", "legal action",  │  │
    │  │   ... (16 terms)                                        │  │
    │  │ → flag: "Threats of consequences" (+25, critical)      │  │
    │  │                                                         │  │
    │  │ FINANCIAL_KEYWORDS: "lottery", "you have won",         │  │
    │  │   "tax refund", ... (16 terms)                         │  │
    │  │ → flag: "Financial bait" (+20, high)                   │  │
    │  │                                                         │  │
    │  │ CREDENTIAL_KEYWORDS: "verify your account",           │  │
    │  │   "reset password", ... (15 terms)                     │  │
    │  │ → flag: "Credential harvesting" (+25, critical)        │  │
    │  └─────────────────────────────────────────────────────────┘  │
    │                         │                                     │
    │                         ▼                                     │
    │  ┌─────────────────────────────────────────────────────────┐  │
    │  │ STRUCTURAL SIGNALS                                      │  │
    │  │                                                         │  │
    │  │ - Generic greeting? (dear user, dear customer)         │  │
    │  │   → "Generic greeting" (+10, medium)                   │  │
    │  │                                                         │  │
    │  │ - Sender header check:                                 │  │
    │  │   • Reply-To differs from From? (+15, high)           │  │
    │  │   • Suspicious sender patterns (+15, high)             │  │
    │  │                                                         │  │
    │  │ - Link checks:                                         │  │
    │  │   • Links to IP address? (+15, high)                  │  │
    │  │   • URL shorteners? (+15, high)                       │  │
    │  │                                                         │  │
    │  │ - Anchor text mismatch:                                │  │
    │  │   "click here" → different host (+20, critical)       │  │
    │  │                                                         │  │
    │  │ - Phone number present? (+5, low)                     │  │
    │  │ - BTC address present? (+15, high)                     │  │
    │  │ - Excessive CAPS (>70%)? (+5, low)                    │  │
    │  │ - Excessive emoji (>3)? (+5, low)                     │  │
    │  └─────────────────────────────────────────────────────────┘  │
    │                         │                                     │
    │                         ▼                                     │
    │  ┌─────────────────────────────────────────────────────────┐  │
    │  │ SCORE & VERDICT                                         │  │
    │  │                                                         │  │
    │  │ raw_score = sum(all flag points)                       │  │
    │  │ phishing_score = min(100, raw_score)                  │  │
    │  │                                                         │  │
    │  │ IF score >= 55:                                       │  │
    │  │   verdict = "PHISHING"                                │  │
    │  │   confidence = "high" if >= 75 else "medium"          │  │
    │  │ ELIF score >= 25:                                     │  │
    │  │   verdict = "SUSPICIOUS"                              │  │
    │  │   confidence = "medium"                               │  │
    │  │ ELSE:                                                  │  │
    │  │   verdict = "SAFE"                                    │  │
    │  │   confidence = "low"                                  │  │
    │  └─────────────────────────────────────────────────────────┘  │
    │                         │                                     │
    │                         ▼                                     │
    │  ┌─────────────────────────────────────────────────────────┐  │
    │  │ PERSIST ANALYSIS TO DB                                  │  │
    │  │                                                         │  │
    │  │ INSERT INTO phishing_analyses                          │  │
    │  │ (user_id, content_type, content_preview,              │  │
    │  │  phishing_score, verdict, flags)                       │  │
    │  │ VALUES (?, ?, ?, ?, ?, ?)                              │  │
    │  └─────────────────────────────────────────────────────────┘  │
    │                         │                                     │
    │                         ▼                                     │
    │  ┌─────────────────────────────────────────────────────────┐  │
    │  │ CHECK WATCHLIST MATCHES                                 │  │
    │  │                                                         │  │
    │  │ Extract sender domains + links from content            │  │
    │  │ match_watchlist(db, user_id, values)                   │  │
    │  │ → Return any matching watchlist entries                │  │
    │  │ → Update last_seen_at on matches                       │  │
    │  └─────────────────────────────────────────────────────────┘  │
    │                         │                                     │
    │                         ▼                                     │
    │  ┌─────────────────────────────────────────────────────────┐  │
    │  │ RETURN RESULT                                            │  │
    │  │ {                                                       │  │
    │  │   analysis_id, phishing_score, verdict,                │  │
    │  │   confidence, flags[], matched_keywords{},             │  │
    │  │   stats{}, watchlist_matches[]                         │  │
    │  │ }                                                       │  │
    │  └─────────────────────────────────────────────────────────┘  │
    │                         │                                     │
    └─────────────────────────┼───────────────────────────────────────┘
                              │
                              ▼
                       END (render
                       phishing meter
                       + flags)
    """)

    # ===== SECTION 8: DATA DICTIONARY =====
    pdf.add_page()
    pdf.chapter_title('Data Dictionary', '8')

    pdf.body_text('The Data Dictionary provides a complete reference for all database tables, columns, data types, constraints, and enumerated values used in the ThreatLens system.')

    pdf.section_title('8.1 Core Tables')

    pdf.subsection_title('Table: users')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key, auto-   │
    │              │ (PK,     │            │         │ increment, indexed   │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ username     │ STRING   │ NOT NULL   │ —       │ Unique login name    │
    │              │ (24)     │            │         │ 3-24 chars [a-zA-Z0 │
    │              │          │            │         │ -9_] only            │
    │              │          │            │         │ Indexed, Unique      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ email        │ STRING   │ NOT NULL   │ —       │ User email address   │
    │              │ (254)    │            │         │ RFC 5322 compliant   │
    │              │          │            │         │ Stored lowercase     │
    │              │          │            │         │ Indexed, Unique      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ password_hash│ STRING   │ NOT NULL   │ —       │ PBKDF2-HMAC-SHA256  │
    │              │ (255)    │            │         │ format:              │
    │              │          │            │         │ pbkdf2_sha256$salt$  │
    │              │          │            │         │ hex_digest           │
    │              │          │            │         │ 210,000 iterations   │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ display_name │ STRING   │ NULLABLE   │ NULL    │ Optional friendly     │
    │              │ (50)     │            │         │ name for display     │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ is_admin     │ BOOLEAN  │ NOT NULL   │ FALSE   │ Admin privilege flag  │
    │              │          │            │         │ (added post-launch)  │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Account creation     │
    │              │          │            │         │ timestamp (UTC)      │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.subsection_title('Table: auth_tokens')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    │              │ (PK,     │            │         │                      │
    │              │ INDEXED) │            │         │                      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ token        │ STRING   │ NOT NULL   │ —       │ Bearer token (64 hex │
    │              │ (64)     │            │         │ chars, random)       │
    │              │          │            │         │ Indexed, Unique      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NOT NULL   │ —       │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: CASCADE   │
    │              │ INDEXED) │            │         │                       │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Token creation time  │
    │              │          │            │         │ (UTC)                │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ expires_at   │ DATETIME │ NOT NULL   │ —       │ Token expiry (30     │
    │              │          │            │         │ days from creation)  │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.add_page()
    pdf.subsection_title('Table: scans')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    │              │ (PK,     │            │         │ Auto-increment       │
    │              │ INDEXED) │            │         │                      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NULLABLE   │ NULL    │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: SET NULL  │
    │              │ INDEXED) │            │         │ Null = anonymous     │
    │              │          │            │         │ scan                 │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ url          │ STRING   │ —          │ —       │ Normalized URL       │
    │              │ (2048)   │            │         │ (submitted URL)      │
    │              │          │            │         │ Indexed              │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ risk_score   │ INTEGER  │ —          │ —       │ Risk score 0-100    │
    │              │          │            │         │ (100 = safest)       │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ verdict      │ STRING   │ —          │ —       │ Classification:      │
    │              │ (50)     │            │         │ SAFE, LOW RISK,      │
    │              │          │            │         │ SUSPICIOUS,          │
    │              │          │            │         │ DANGEROUS            │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ summary      │ TEXT     │ —          │ "{}"    │ JSON summary of scan │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ findings     │ TEXT     │ —          │ "[]"    │ JSON array of        │
    │              │          │            │         │ itemized findings    │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Scan timestamp       │
    │              │          │            │         │ (UTC, Indexed)       │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.subsection_title('Table: phishing_analyses')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NULLABLE   │ NULL    │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: SET NULL  │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ content_type │ STRING   │ —          │ "email" │ email | sms |        │
    │              │ (50)     │            │         │ page_text            │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ content_preview│ STRING │ —          │ ""      │ First 400 chars of   │
    │              │ (500)    │            │         │ analyzed content     │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ phishing_score│ INTEGER │ —          │ —       │ 0-100 (higher = more │
    │              │          │            │         │ likely phishing)     │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ verdict      │ STRING   │ —          │ —       │ SAFE, SUSPICIOUS,    │
    │              │ (50)     │            │         │ PHISHING             │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ flags        │ TEXT     │ —          │ "[]"    │ JSON array of        │
    │              │          │            │         │ detection flags      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Analysis timestamp   │
    │              │          │            │         │ (UTC, Indexed)       │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.add_page()
    pdf.subsection_title('Table: watchlist_entries')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NOT NULL   │ —       │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: CASCADE   │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ kind         │ STRING   │ NOT NULL   │ —       │ sender | domain |    │
    │              │ (10)     │            │         │ url                  │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ value        │ STRING   │ NOT NULL   │ —       │ Email address,       │
    │              │ (2048)   │            │         │ domain, or URL       │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ note         │ STRING   │ NULLABLE   │ NULL    │ Optional user note    │
    │              │ (200)    │            │         │ (max 200 chars)      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ When added (UTC)     │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ last_seen_at │ DATETIME │ NULLABLE   │ NULL    │ Last matched (UTC)   │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.subsection_title('Table: audit_log')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NULLABLE   │ NULL    │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: SET NULL  │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ action       │ STRING   │ NOT NULL   │ —       │ user.promote,        │
    │              │ (100)    │            │         │ user.demote,         │
    │              │          │            │         │ user.delete          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ detail       │ TEXT     │ NULLABLE   │ NULL    │ JSON or human-       │
    │              │          │            │         │ readable detail      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ ip_address   │ STRING   │ NULLABLE   │ NULL    │ Client IP address    │
    │              │ (45)     │            │         │ (IPv4/IPv6)          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Action timestamp     │
    │              │          │            │         │ (UTC, Indexed)       │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.subsection_title('Table: api_keys')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NOT NULL   │ —       │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: CASCADE   │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ key_hash     │ STRING   │ NOT NULL   │ —       │ Hashed API key       │
    │              │ (128)    │            │         │ (unique, indexed)    │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ name         │ STRING   │ —          │ "default"│ Human label          │
    │              │ (100)    │            │         │                       │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ prefix       │ STRING   │ NOT NULL   │ —       │ First 8 chars        │
    │              │ (8)      │            │         │ (for display)        │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ is_active    │ BOOLEAN  │ NOT NULL   │ TRUE    │ Currently active?    │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ last_used_at │ DATETIME │ NULLABLE   │ NULL    │ Last used (UTC)      │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Creation time (UTC)  │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ expires_at   │ DATETIME │ NULLABLE   │ NULL    │ Optional expiry      │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.subsection_title('Table: webhooks')
    pdf.code_block("""
    ┌──────────────┬──────────┬────────────┬─────────┬──────────────────────┐
    │ COLUMN NAME  │ TYPE     │ NULLABLE   │ DEFAULT │ DESCRIPTION          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ id           │ INTEGER  │ NOT NULL   │ AUTOINC │ Primary key          │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ user_id      │ INTEGER  │ NOT NULL   │ —       │ FK → users.id        │
    │              │ (FK,     │            │         │ On delete: CASCADE   │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ url          │ STRING   │ NOT NULL   │ —       │ Webhook endpoint     │
    │              │ (2048)   │            │         │ (HTTP/S only)        │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ secret       │ STRING   │ NOT NULL   │ —       │ HMAC-SHA256 secret   │
    │              │ (64)     │            │         │ (32 hex chars)       │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ events       │ TEXT     │ —          │ '["scan. │ JSON array of        │
    │              │          │            │  dangerous]"│ event types: scan.  │
    │              │          │            │ '       │ dangerous, scan.*    │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ is_active    │ BOOLEAN  │ NOT NULL   │ TRUE    │ Currently active?    │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ last_triggered│ DATETIME│ NULLABLE   │ NULL    │ Last triggered (UTC) │
    ├──────────────┼──────────┼────────────┼─────────┼──────────────────────┤
    │ created_at   │ DATETIME │ NOT NULL   │ utcnow()│ Creation (UTC)       │
    └──────────────┴──────────┴────────────┴─────────┴──────────────────────┘
    """)

    pdf.add_page()
    pdf.section_title('8.2 Enumerated Values Reference')
    pdf.code_block("""
    VERDICT VALUES (ScanRecord.verdict, PhishingAnalysis.verdict):
    ┌────────────────────────────────────────────────────────────────────┐
    │ • SAFE          — URL/content appears legitimate                   │
    │ • LOW RISK      — Minor concerns, generally safe (scans only)     │
    │ • SUSPICIOUS    — Notable red flags, warrants caution              │
    │ • DANGEROUS     — High-risk URL (scan verdict only)                │
    │ • PHISHING      — Likely phishing content (phishing only)          │
    └────────────────────────────────────────────────────────────────────┘

    RISK LEVEL VALUES (RiskReport.risk_level):
    ┌────────────────────────────────────────────────────────────────────┐
    │ • safe          — Score ≥ 85                                      │
    │ • low          — Score ≥ 70 and < 85                             │
    │ • suspicious   — Score ≥ 40 and < 70                             │
    │ • critical     — Score < 40                                      │
    └────────────────────────────────────────────────────────────────────┘

    WATCHLIST ENTRY KIND VALUES:
    ┌────────────────────────────────────────────────────────────────────┐
    │ • sender       — Email address (e.g. scammer@gmail.com)           │
    │ • domain       — Domain name (e.g. paypal-verify.tk)              │
    │ • url          — Full URL (e.g. https://fake-login.xyz)           │
    └────────────────────────────────────────────────────────────────────┘

    CONTENT TYPE VALUES:
    ┌────────────────────────────────────────────────────────────────────┐
    │ • email        — Email body content                                │
    │ • sms          — SMS/text message content                          │
    │ • page_text    — Web page text content                             │
    └────────────────────────────────────────────────────────────────────┘

    FINDING SEVERITY VALUES:
    ┌────────────────────────────────────────────────────────────────────┐
    │ • critical     — Severe security issue                             │
    │ • high         — Significant concern                                │
    │ • medium       — Moderate concern                                   │
    │ • low          — Minor concern                                      │
    │ • info         — Informational only (no score impact)              │
    │ • positive     — Positive signal (increases score)                 │
    └────────────────────────────────────────────────────────────────────┘

    THREAT INTEL STATUS VALUES:
    ┌────────────────────────────────────────────────────────────────────┐
    │ • ok           — Provider query succeeded                          │
    │ • skipped      — API key not configured                           │
    │ • error        — Provider query failed                             │
    └────────────────────────────────────────────────────────────────────┘

    AUTH ACTION VALUES (AuditLog.action):
    ┌────────────────────────────────────────────────────────────────────┐
    │ • user.promote  — User promoted to admin                          │
    │ • user.demote  — User demoted from admin                          │
    │ • user.delete  — User deleted                                     │
    └────────────────────────────────────────────────────────────────────┘

    WEBHOOK EVENT TYPES:
    ┌────────────────────────────────────────────────────────────────────┐
    │ • scan.dangerous  — Fired when scan returns DANGEROUS verdict      │
    │ • *               — Wildcard (all events)                          │
    └────────────────────────────────────────────────────────────────────┘
    """)

    pdf.section_title('8.3 Reference Data (Hardcoded)')
    pdf.code_block("""
    SUSPICIOUS TLDs (57 high-risk TLDs):
    tk, ml, ga, cf, gq, top, xyz, work, click, loan, men, win, bid,
    date, racing, review, stream, download, gdn, country, kim, science,
    party, link, wang, xin, monster, rest, fit, accountant, trade,
    website, site, online, live, club, cyou, icu, buzz, quest, cam,
    mom, lol, zip, mov

    URL SHORTENERS (21 known services):
    bit.ly, tinyurl.com, t.co, goo.gl, ow.ly, is.gd, buff.ly,
    rebrand.ly, cutt.ly, shorturl.at, rb.gy, tiny.cc, s.id,
    v.gd, soo.gd, t.ly, lnkd.in, x.co, qr.ae, cutt.us

    POPULAR BRANDS (56 brands with official domains):
    google (google.com), youtube (youtube.com), gmail (gmail.com),
    facebook (facebook.com), instagram (instagram.com), whatsapp (whatsapp),
    twitter (twitter.com, x.com), telegram (telegram.org), tiktok,
    snapchat, paypal (paypal.com), amazon (amazon.com), ebay (ebay.com),
    apple (apple.com), icloud (icloud.com), microsoft (microsoft.com),
    outlook (outlook.com), office (office.com), onedrive (onedrive.com),
    netflix (netflix.com), spotify (spotify.com), twitch (twitch.tv),
    linkedin (linkedin.com), github (github.com), dropbox (dropbox.com),
    steam (steampowered.com), epicgames (epicgames.com),
    coinbase (coinbase.com), binance (binance.com), blockchain (blockchain),
    metamask (metamask.io), chase (chase.com), wellsfargo (wellsfargo.com),
    bankofamerica (bankofamerica.com), citibank (citi.com),
    capitalone (capitalone.com), hsbc (hsbc.com), barclays (barclays.co.uk),
    fedex (fedex.com), ups (ups.com), usps (usps.com), dhl (dhl.com),
    walmart (walmart.com), target (target.com), bestbuy (bestbuy.com),
    airbnb (airbnb.com), booking (booking.com), expedia (expedia.com),
    adobe (adobe.com), salesforce (salesforce.com), wordpress (wordpress.com)

    CREDENTIAL HINTS (15 keywords):
    login, signin, verify, secure, account, update, confirm,
    wallet, auth, password, recover, unlock, validate, billing

    FREE MAIL DOMAINS (15 providers):
    gmail.com, googlemail.com, yahoo.com, yahoo.co.uk, hotmail.com,
    outlook.com, live.com, aol.com, icloud.com, protonmail.com,
    proton.me, mail.com, gmx.com, zoho.com
    """)

    # ===== SECTION 9: FINALIZED DATABASE SCHEMA =====
    pdf.add_page()
    pdf.chapter_title('Finalized Database Schema', '9')

    pdf.section_title('9.1 Complete Entity-Relationship Diagram')
    pdf.code_block("""
    ┌──────────────────────────────────────────────────────────────────────┐
    │                         THREATLENS ER DIAGRAM                        │
    └──────────────────────────────────────────────────────────────────────┘

                               ┌──────────────────┐
                               │     users        │
                               │ ◄═══════════════ │ 1:N  (auth_tokens)
                               │ id (PK)          │
                               │ username (UNIQ)  │
                               │ email (UNIQ)     │                   ┌──────────────────┐
                               │ password_hash    │                   │   auth_tokens    │
                               │ display_name     │                   │                  │
                               │ is_admin         │                   │ id (PK)          │
                               │ created_at       │                   │ token (UNIQ)     │
                               └──────┬───────────┘                   │ user_id (FK→users)│
                                      │ 1:N                           │ created_at       │
                                      │                               │ expires_at       │
                    ┌───────────────────┤                               └──────────────────┘
                    │                   │ 1:N
                    │                   │
                    ▼                   ▼
         ┌────────────────────┐  ┌────────────────────┐
         │     scans          │  │  phishing_analyses │
         ├────────────────────┤  ├────────────────────┤
         │ id (PK)            │  │ id (PK)            │
         │ user_id (FK→users) │  │ user_id (FK→users) │
         │   ON DELETE SET NULL│  │   ON DELETE SET NULL│
         │ url (INDEXED)      │  │ content_type       │
         │ risk_score         │  │ content_preview    │
         │ verdict            │  │ phishing_score     │
         │ summary (JSON)     │  │ verdict            │
         │ findings (JSON)    │  │ flags (JSON)       │
         │ created_at (IDX)   │  │ created_at (IDX)   │
         └────────────────────┘  └────────────────────┘
              │ 1:N                    │ 1:N
              │                        │
              ▼                        ▼
         ┌────────────────────┐  ┌────────────────────┐
         │    audit_log       │  │   watchlist_entries│
         ├────────────────────┤  ├────────────────────┤
         │ id (PK)            │  │ id (PK)            │
         │ user_id (FK→users) │  │ user_id (FK→users) │
         │   ON DELETE SET NULL│  │   ON DELETE CASCADE│
         │ action             │  │ kind               │
         │ detail             │  │ value              │
         │ ip_address         │  │ note               │
         │ created_at (IDX)   │  │ created_at         │
         └────────────────────┘  │ last_seen_at       │
                                  └────────────────────┘
                                      │ 1:N
                                      │
                                      ▼
                              ┌────────────────────┐
                              │     api_keys       │
                              ├────────────────────┤
                              │ id (PK)            │
                              │ user_id (FK→users) │
                              │   ON DELETE CASCADE│
                              │ key_hash (UNIQ)    │
                              │ name               │
                              │ prefix             │
                              │ is_active          │
                              │ last_used_at       │
                              │ created_at         │
                              │ expires_at         │
                              └────────────────────┘
                                      │ 1:N
                                      │
                                      ▼
                              ┌────────────────────┐
                              │     webhooks       │
                              ├────────────────────┤
                              │ id (PK)            │
                              │ user_id (FK→users) │
                              │   ON DELETE CASCADE│
                              │ url                │
                              │ secret             │
                              │ events (JSON)      │
                              │ is_active          │
                              │ last_triggered_at  │
                              │ created_at         │
                              └────────────────────┘

    RELATIONSHIPS SUMMARY:
    users 1 ──┬──► N auth_tokens          (A user has many tokens)
              ├──► N scans                 (A user has many scans)
              ├──► N phishing_analyses     (A user has many phishing analyses)
              ├──► N watchlist_entries     (A user has many watchlist items)
              ├──► N audit_log             (A user generates audit entries)
              ├──► N api_keys              (A user has many API keys)
              └──► N webhooks              (A user has many webhooks)

    CASCADE vs SET NULL:
    • CASCADE: Delete user → delete their tokens, watchlist, API keys,
      webhooks (dependent data)
    • SET NULL: Delete user → keep scans/analyses/audit but anonymize
      (historical record preservation)
    """)

    pdf.add_page()
    pdf.section_title('9.2 Index Strategy')
    pdf.code_block("""
    ┌────────────────────────────────────────────────────────────────────────────┐
    │                         INDEX STRATEGY                                       │
    ├────────────────────────────────────────────────────────────────────────────┤
    │  Table             │ Columns Indexed         │ Purpose                     │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  users             │ id (PK)                 │ Primary lookup              │
    │                    │ username (UNIQUE)       │ Login lookup                │
    │                    │ email (UNIQUE)          │ Login by email              │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  auth_tokens       │ id (PK)                 │ Primary lookup              │
    │                    │ token (UNIQUE)          │ Token validation            │
    │                    │ user_id                 │ User's tokens lookup        │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  scans             │ id (PK)                 │ Primary lookup              │
    │                    │ url                     │ URL search/filter           │
    │                    │ user_id                 │ User's scans lookup         │
    │                    │ created_at              │ Chronological ordering      │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  phishing_analyses │ id (PK)                 │ Primary lookup              │
    │                    │ user_id                 │ User's analyses lookup      │
    │                    │ created_at              │ Chronological ordering      │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  watchlist_entries │ id (PK)                 │ Primary lookup              │
    │                    │ user_id                 │ User's watchlist lookup     │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  audit_log         │ id (PK)                 │ Primary lookup              │
    │                    │ user_id                 │ User's actions lookup       │
    │                    │ created_at              │ Chronological ordering      │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  api_keys          │ id (PK)                 │ Primary lookup              │
    │                    │ key_hash (UNIQUE)       │ Key validation              │
    │                    │ user_id                 │ User's keys lookup          │
    │  ──────────────────┼─────────────────────────┼──────────────────────────── │
    │  webhooks          │ id (PK)                 │ Primary lookup              │
    │                    │ user_id                 │ User's webhooks lookup      │
    └────────────────────────────────────────────────────────────────────────────┘
    """)

    pdf.section_title('9.3 Schema Evolution History')
    pdf.code_block("""
    INITIAL SCHEMA (v1.0):
    ─────────────────────
    • users (id, username, email, password_hash, display_name, created_at)
    • auth_tokens (id, token, user_id, created_at, expires_at)
    • watchlist_entries (id, user_id, kind, value, note, created_at,
      last_seen_at)
    • scans (id, url, risk_score, verdict, summary, findings, created_at)
    • phishing_analyses (id, content_type, content_preview, phishing_score,
      verdict, flags, created_at)
    • audit_log (id, user_id, action, detail, ip_address, created_at)

    SCHEMA UPDATE (v1.1+ - _ensure_legacy_columns in main.py):
    ────────────────────────────────────────────────────
    • Added users.is_admin (BOOLEAN DEFAULT 0) — added via ALTER TABLE
      for existing databases (new DBs get it from ORM metadata)
    • Added scans.user_id (INTEGER, FK to users.id ON DELETE SET NULL)
    • Added phishing_analyses.user_id (INTEGER, FK to users.id ON DELETE
      SET NULL)

    WHY user_id uses SET NULL:
    ─────────────────────────
    Historical scans/analyses are preserved even if a user deletes their
    account. The record remains but is disassociated from the deleted user.

    WHY watchlist/api_keys/webhooks use CASCADE:
    ────────────────────────────────────────────
    These are strictly user-owned — if the user is deleted, their watchlist
    entries, API keys, and webhook subscriptions should be removed.
    """)

    pdf.section_title('9.4 JSON Column Structures')
    pdf.code_block("""
    SCAN.summary JSON Structure:
    {
      "request": {
        "submitted_url": "https://example.com",
        "normalized_url": "https://example.com/",
        "scheme": "https",
        "host": "example.com",
        "port": 443,
        "path": "/",
        "is_ip": false,
        "ip_version": null,
        "domain": "example",
        "tld": "com",
        "registrable_domain": "example.com",
        "subdomain": "",
        "url_length": 22,
        "has_https": true
      },
      "category_totals": {
        "Heuristics": -20,
        "Metadata": -10,
        "Threat Intelligence": -50
      },
      "metadata": {
        "whois": { ... },
        "ssl": { ... },
        "http": { ... }
      },
      "threat_intel": {
        "virustotal": { "status": "ok", "malicious": 5, ... },
        "google_safe_browsing": { "status": "ok", "threatened": true, ... },
        "phishtank": { "status": "ok", "in_database": false }
      },
      "providers": {
        "virustotal": true,
        "google_safe_browsing": true,
        "phishtank": true
      },
      "duration_ms": 3420,
      "scanned_at": "2026-09-07T12:00:00.000000+00:00"
    }

    SCAN.findings JSON Structure (array):
    [
      {
        "label": "Typosquatting / brand impersonation",
        "points": -35,
        "severity": "critical",
        "detail": "'example' is 1 character away from 'exampel'",
        "category": "Heuristics"
      },
      {
        "label": "Domain registered very recently",
        "points": -40,
        "severity": "critical",
        "detail": "Domain is 3 days old (< 14 days)",
        "category": "Metadata"
      }
    ]

    PHISHING_ANALYSES.flags JSON Structure (array):
    [
      {
        "label": "Urgency pressure",
        "points": 20,
        "severity": "high",
        "detail": "Uses urgency language: urgent, immediately"
      },
      {
        "label": "Credential harvesting language",
        "points": 25,
        "severity": "critical",
        "detail": "Asked to verify/enter credentials: verify your account"
      }
    ]

    WEBHOOKS.events JSON Structure (array):
    ["scan.dangerous", "scan.*"]
    """)

    pdf.section_title('9.5 Database Configuration')
    pdf.code_block("""
    # backend/app/config.py → Settings
    DATABASE_URL: str = os.getenv("DATABASE_URL", "sqlite:///./threatshield.db")

    # backend/app/database.py
    engine = create_engine(
        settings.DATABASE_URL,
        connect_args={"check_same_thread": False} if sqlite else {},
        pool_pre_ping=True
    )
    SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
    Base = DeclarativeBase()  # SQLAlchemy 2.0 style
    """)

    pdf.section_title('9.6 Key Design Decisions')
    pdf.code_block("""
    ┌────────────────────────────────────────────────────────────────────────────┐
    │                         KEY DESIGN DECISIONS                                │
    ├────────────────────────────────────────────────────────────────────────────┤
    │  Decision              │ Rationale                                        │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  SQLite               │ Single-file, zero-config, suitable for small-     │
    │  over PostgreSQL     │ medium deployments. Easy to backup (copy file).   │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  SQLAlchemy 2.0 ORM  │ Type-safe, async-ready, declarative models.        │
    │                       │ Future migration to PostgreSQL just requires       │
    │                       │ changing DATABASE_URL.                             │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  Bearer tokens in DB │ Simple revocation (DELETE from auth_tokens).      │
    │  (not JWT)           │ No clock skew issues. 30-day TTL.                 │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  PBKDF2-HMAC-SHA256  │ No external crypto dependencies. 210,000          │
    │  (stdlib only)       │ iterations is strong against brute force.         │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  SET NULL on user    │ Preserve historical data. Scans remain visible    │
    │  deletion for scans  │ but anonymized.                                  │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  CASCADE on user     │ These are purely user-owned — if user deleted,    │
    │  deletion for        │ their watchlist, keys, webhooks removed.          │
    │  tokens/watchlist/   │                                                   │
    │  keys/webhooks       │                                                   │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  JSON columns for    │ Flexible schema for evolving report structure     │
    │  summary/findings/   │ without migrations.                               │
    │  flags               │                                                   │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  In-memory rate      │ Simple, sufficient for single-worker. Documented  │
    │  limiter             │ to move to Redis for multi-worker.                │
    │  ─────────────────────┼─────────────────────────────────────────────────│
    │  SSRF protection in  │ Scanner must never be an internal network proxy.  │
    │  metadata.py         │ All outbound connections validated.               │
    └────────────────────────────────────────────────────────────────────────────┘
    """)

    # Save PDF
    from pathlib import Path
    output_dir = Path(__file__).resolve().parent.parent / "docs" / "reports"
    output_dir.mkdir(parents=True, exist_ok=True)
    output_path = str(output_dir / "ThreatLens_System_Design.pdf")
    pdf.output(output_path)
    print(f'PDF generated: {output_path}')
    print(f'Total pages: {pdf.page_no()}')

if __name__ == '__main__':
    generate_pdf()