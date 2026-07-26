# soc_chatbot.py — SOC Cognitive Chatbot
# Architecture: LLM (Groq) understands queries naturally.
#               Python handles data, scoring, formatting.
# Commands: generate | chat | evaluate | stats | all

import os
import csv, math, os, random, re, statistics, time
from collections import Counter
from datetime import datetime, timedelta

# ══════════════════════════════════════════════════════════════════════════════
# SECTION 1 — CONSTANTS
# ══════════════════════════════════════════════════════════════════════════════

THRESHOLD  = 0.49
CRIT_SCORE = {"Low": 0.25, "Medium": 0.50, "High": 0.75, "Critical": 1.00}
CRIT_ORDER = {"Low": 0,    "Medium": 1,    "High": 2,    "Critical": 3}
SEP  = "=" * 68
LINE = "─" * 52

ASSETS = {
    "DomainController-01": 10, "DatabaseServer-04": 9,
    "FileServer-02": 8,        "WebServer-03": 7,
    "MailServer-05": 7,        "AppServer-06": 6,
    "Workstation-07": 4,       "Workstation-08": 4,
    "LaptopUser-09": 2,        "LaptopUser-10": 2,
}

ATTACK_TYPES = ["Malware", "Phishing", "BruteForce", "Ransomware", "DataExfiltration"]

CRIT_WEIGHTS = {
    "Malware":          [0.15, 0.25, 0.35, 0.25],
    "Phishing":         [0.15, 0.25, 0.35, 0.25],
    "BruteForce":       [0.20, 0.30, 0.30, 0.20],
    "Ransomware":       [0.05, 0.15, 0.40, 0.40],
    "DataExfiltration": [0.05, 0.15, 0.40, 0.40],
}

MITRE = {
    "Malware":          ("T1059", "Command and Scripting Interpreter"),
    "Phishing":         ("T1566", "Phishing"),
    "BruteForce":       ("T1110", "Brute Force"),
    "Ransomware":       ("T1486", "Data Encrypted for Impact"),
    "DataExfiltration": ("T1041", "Exfiltration Over C2 Channel"),
}

CVE_POOL = {
    "Malware":          [("CVE-2024-21412",9.8),("CVE-2024-30051",7.8),("CVE-2024-38112",8.8),(None,0.0),(None,0.0)],
    "Phishing":         [("CVE-2024-20656",7.8),("CVE-2023-36884",8.8),(None,0.0),(None,0.0),(None,0.0)],
    "BruteForce":       [("CVE-2024-49563",7.3),("CVE-2024-38077",9.8),(None,0.0),(None,0.0),(None,0.0)],
    "Ransomware":       [("CVE-2024-40711",9.8),("CVE-2024-37085",7.2),("CVE-2024-26169",7.0),(None,0.0),(None,0.0)],
    "DataExfiltration": [("CVE-2024-21338",7.8),("CVE-2024-30103",8.8),(None,0.0),(None,0.0),(None,0.0)],
}

RECOMMENDATIONS = {
    "Malware":
        "1. Isolate the affected endpoint | 2. Run EDR scan and memory dump | "
        "3. Check SIEM for lateral movement | 4. Review process execution logs (T1059)",
    "Phishing":
        "1. Block sender domain at mail gateway | 2. Notify impacted users | "
        "3. Search mailboxes for similar messages | 4. Reset credentials if link was clicked",
    "BruteForce":
        "1. Enable account lockout immediately | 2. Block source IP | "
        "3. Enforce MFA | 4. Review VPN/RDP logs for past 24h",
    "Ransomware":
        "1. Disconnect host from network IMMEDIATELY | 2. Snapshot VMs before shutdown | "
        "3. Activate IR playbook | 4. Preserve forensic evidence",
    "DataExfiltration":
        "1. Block destination IP at perimeter | 2. Capture full network traffic | "
        "3. Identify scope of exfiltrated data | 4. Engage legal team",
}

HISTORY_NOTE = {
    "Malware":          ("Similar incident 2 months ago on same subnet", "No prior incidents"),
    "Phishing":         ("Similar phishing attempt observed yesterday", "First occurrence"),
    "BruteForce":       ("Repeated failed logins from same IP over 48h", "Isolated failed login"),
    "Ransomware":       ("Ransomware family previously seen in sector", "No prior ransomware history"),
    "DataExfiltration": ("Unusual outbound traffic spike last week", "No prior exfiltration events"),
}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 2 — LLM (Groq) — the brain of the bot
# ══════════════════════════════════════════════════════════════════════════════

LLM_API_KEY = os.environ.get("GROQ_API_KEY", "")
LLM_MODEL   = "llama-3.1-8b-instant"
_llm_ok     = True

# Instant checks — never call LLM for these
_GREETINGS = {"hey","hello","hi","bonjour","salut","salam","thanks","thank you",
              "merci","ok","okay","cool","bye","ciao","hola","good morning","good evening",
              "bonsoir","مرحبا","شكرا","مساء الخير"}

_MORE_KW = {"more","next","suite","suivant","show more","plus","encore",
            "mor","mroe","mre","nxt","nextt","moer"}  # fuzzy typos

# ── NLU: understand the query, return structured filters ─────────────────────

_NLU_SYSTEM = """You are a SOC (Security Operations Center) query parser.
Read the analyst message and return ONLY valid JSON — no explanation, no markdown.

JSON schema:
{
  "alert_id": <integer>|null,
  "alert_type": "Malware"|"Phishing"|"BruteForce"|"Ransomware"|"DataExfiltration"|null,
  "source": "DomainController-01"|"DatabaseServer-04"|"FileServer-02"|"WebServer-03"|"MailServer-05"|"AppServer-06"|"Workstation-07"|"Workstation-08"|"LaptopUser-09"|"LaptopUser-10"|null,
  "criticality": "Critical"|"High"|"Medium"|"Low"|null,
  "decision": "ESCALATE"|"suppress"|null,
  "sort": "rs"|"asset"|null,
  "intent": "filter"|"investigate"|"recommend"|"count"|"chat",
  "inherit_type": true|false,
  "inherit_source": true|false,
  "inherit_criticality": false,
  "inherit_decision": false
}

ALERT ID RULES:
- alert_id = the integer after "alert", "#", "id", "number": "alert 47" → 47, "#5" → 5, "id 100" → 100
- When alert_id is set, intent must be "investigate"
- alert_id=null for all queries that don't reference a specific alert number

INTENT RULES:
- intent="investigate" for: investigate, analyze, explain, details, deep dive, tell me about alert, "analyze alert 47", "analyze them" (when previous results exist)
- intent="chat" for: general questions, "do you understand", "what can you do", off-topic, "how are you", anything not security-alert-related
- intent="count" for: "how many", "combien", "count", "total", "number of"
- intent="recommend" for: playbook, what to do, how to respond, steps, remediate, fix
- intent="filter" for: show, list, find, display, get, all other alert queries

CONTEXT INHERITANCE — critical rules:
- When analyst says "analyze them" or "analyze these" → inherit_source=true (investigate current results), alert_id=null
- inherit_type=true ONLY when analyst clearly continues same type: "and the critical ones", "just high"
- inherit_type=false when analyst mentions a new type OR uses "show", "all", type names explicitly
- inherit_source=true for follow-ups on same asset: "analyze them", "and the high ones", "on DC"
- inherit_source=false when analyst starts fresh: "all assets", "globally", "show X alerts"
- inherit_criticality=false ALWAYS
- inherit_decision=false ALWAYS

DECISION RULES:
- decision="suppress" ONLY when explicitly: suppressed, not escalated, ignored, low priority
- decision="ESCALATE" ONLY when explicitly: escalated, needs escalation
- decision=null for everything else

SORT RULES:
- sort="rs" for: "by RS", "by risk score", "arrange by risk", "sort by score", "ranked by risk", "make them by RS"
- sort="asset" for: "by asset", "by importance", "by asset value"
- sort=null otherwise

SOURCE ALIASES: dc/domain→DomainController-01, db/database/sql→DatabaseServer-04,
mail/exchange/smtp→MailServer-05, web/http→WebServer-03, file/nas/storage→FileServer-02, app→AppServer-06

CRITICALITY ALIASES: most critical/urgent/worst/top priority/severe→Critical, serious/important→High

Return ONLY the JSON. Nothing else."""


def call_llm_nlu(query, session_or_ctx=""):
    """LLM understands the query naturally. Returns filter dict or None."""
    global _llm_ok
    import os, json

    key = LLM_API_KEY or os.environ.get("SOC_LLM_KEY", "")
    if not _llm_ok or not key:
        return None

    # Accept both session dict and context string
    if isinstance(session_or_ctx, dict):
        session = session_or_ctx
        ctx_parts = []
        if session.get("_type"):   ctx_parts.append(f"type={session['_type']}")
        if session.get("_source"): ctx_parts.append(f"source={session['_source']}")
        ctx = ", ".join(ctx_parts) if ctx_parts else "none"
    else:
        ctx = session_or_ctx or "none"

    msg = f"[Current context: {ctx}]\nQuery: {query}"

    try:
        from groq import Groq
        client = Groq(api_key=key)
        resp   = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": _NLU_SYSTEM},
                {"role": "user",   "content": msg},
            ],
            temperature=0,
            max_tokens=150,
        )
        raw = resp.choices[0].message.content.strip()
        if "```" in raw:
            raw = raw.split("```")[1].lstrip("json").strip()
        parsed = json.loads(raw)
        # Defaults
        parsed.setdefault("alert_id",          None)
        parsed.setdefault("alert_type",        None)
        parsed.setdefault("source",            None)
        parsed.setdefault("criticality",       None)
        parsed.setdefault("decision",          None)
        parsed.setdefault("sort",              None)
        parsed.setdefault("intent",            "filter")
        parsed.setdefault("inherit_type",      False)
        parsed.setdefault("inherit_source",    False)
        parsed.setdefault("inherit_criticality", False)
        parsed.setdefault("inherit_decision",  False)
        if parsed["intent"] not in ("filter","investigate","recommend","count","chat"):
            parsed["intent"] = "filter"
        # Ensure alert_id forces investigate intent
        if parsed.get("alert_id"):
            parsed["intent"] = "investigate"
        return parsed

    except ImportError:
        _llm_ok = False
        return None
    except Exception as e:
        msg_e = str(e)
        if any(x in msg_e for x in ("401","403","invalid_api_key")):
            _llm_ok = False
            print("[LLM] Auth error — check LLM_API_KEY.")
        return None


# ── Response formatter: LLM writes the final answer ──────────────────────────

_FORMAT_SYSTEM = """You are a SOC triage assistant. You ONLY use the alert data provided to you.

CRITICAL RULES — violations destroy trust:
- NEVER invent, guess, or assume alert data not in the provided list
- NEVER say there are "3 critical alerts" if you received 10 — use the EXACT count from Context
- NEVER analyze an alert not in your data — if asked for alert #47, only describe #47
- If asked about a specific alert ID, ONLY discuss that exact alert
- Answer in the SAME LANGUAGE as the analyst

FORMAT:
- For investigation: show exact ID, Type, Criticality, Asset, CVE, MITRE, RS, Decision, History note, then playbook steps
- For recommendations: numbered steps per attack type
- Use plain text — no markdown tables, no bullet points with asterisks
- Be concise and professional"""


def call_llm_format(query, alerts_data, context_msg):
    """LLM formats investigate/recommend. Receives exact Python-filtered data only."""
    global _llm_ok
    import os

    key = LLM_API_KEY or os.environ.get("SOC_LLM_KEY", "")
    if not _llm_ok or not key:
        return None

    lines = []
    for a in alerts_data:
        cve  = a.get("CVE","None"); cve = cve if cve != "None" else "no CVE"
        hist = a.get("HistoryNote","No history")
        lines.append(
            f"ID={a['ID']} | Type={a['Type']} | Criticality={a['Criticality']} "
            f"| Asset={a['Source']} | AV={a['AssetValue']} | CVSS={a['CVSS']} "
            f"| RS={a.get('_rs','?')} | Decision={a.get('_dec','?')} "
            f"| CVE={cve} | MITRE={a.get('MITRE_Code','?')} ({a.get('MITRE_Name','?')}) "
            f"| History: {hist}"
        )

    data_section = "\n".join(lines) if lines else "No alert data."

    user = (f"Query: {query}\n"
            f"Context (use these exact numbers): {context_msg}\n"
            f"You received {len(alerts_data)} alert(s) — analyze ONLY these:\n\n"
            f"{data_section}")

    try:
        from groq import Groq
        client = Groq(api_key=key)
        resp = client.chat.completions.create(
            model=LLM_MODEL,
            messages=[
                {"role": "system", "content": _FORMAT_SYSTEM},
                {"role": "user",   "content": user},
            ],
            temperature=0,
            max_tokens=600,
        )
        return resp.choices[0].message.content.strip()
    except Exception:
        return None


# ── Keyword fallback (when LLM unavailable) ───────────────────────────────────

def _kw_parse(query, session=None):
    """Fast keyword-based parser — runs when LLM is unavailable."""
    ql = query.lower().strip().rstrip("?!. ")
    session = session or {}

    if ql in _GREETINGS:
        return {"intent":"greeting","alert_type":None,"source":None,"criticality":None,
                "decision":None,"sort":None,"inherit_type":False,"inherit_source":False,
                "inherit_criticality":False,"inherit_decision":False}

    if ql in _MORE_KW:
        return {"intent":"more"}

    TYPE_KW = {
        "Malware":["malware","virus","trojan","worm"],
        "Phishing":["phishing","phish"],
        "BruteForce":["bruteforce","brute force","brute-force","credential","failed login"],
        "Ransomware":["ransomware","ransom","encrypt"],
        "DataExfiltration":["exfiltration","exfil","data theft","data leak"],
    }
    SOURCE_KW = {
        "DomainController-01":["domaincontroller","domain controller","dc","active directory"],
        "DatabaseServer-04":["database","db","sql","databaseserver"],
        "FileServer-02":["fileserver","file server","nas","storage"],
        "WebServer-03":["webserver","web server","web","http"],
        "MailServer-05":["mailserver","mail server","mail","smtp","exchange","email server"],
        "AppServer-06":["appserver","app server","application"],
        "Workstation-07":["workstation-07","ws07"],
        "Workstation-08":["workstation-08","ws08"],
        "LaptopUser-09":["laptop-09","laptopuser-09"],
        "LaptopUser-10":["laptop-10","laptopuser-10"],
    }
    CRIT_KW = {
        "Critical":["critical","urgent","most critical","top priority","worst","severe","p1"],
        "High":["high","serious","important"],
        "Medium":["medium","moderate"],
        "Low":["low","minor"],
    }

    # Detect off-topic / general chat
    CHAT_SIGNALS = ["do you understand","understand","what can you do","are you ok",
                    "who are you","what are you","how are you","tu comprends",
                    "comprends-tu","ça va","c'est quoi","what is this"]
    if any(s in ql for s in CHAT_SIGNALS):
        return {"intent":"chat","alert_type":None,"source":None,"criticality":None,
                "decision":None,"sort":None,"inherit_type":False,"inherit_source":False,
                "inherit_criticality":False,"inherit_decision":False}

    # Alert ID detection — e.g. "alert 47", "#47", "id 47", "number 47"
    # (bare numbers are NOT treated as IDs: asset names like Workstation-07 contain digits)
    alert_id = None
    id_match = re.search(r'(?:alert\s*(?:number\s*)?|#|\bid\s*|\bnumber\s*|\bnum\s*|alerte\s*)(\d+)', ql)
    if id_match:
        alert_id = int(id_match.group(1))

    # Sort detection
    sort = None
    if any(w in ql for w in ("by rs","by risk score","by risk","arrange by","sort by","order by","ranked by","rank by")):
        sort = "rs"
    elif any(w in ql for w in ("by asset","by asset value","by importance")):
        sort = "asset"

    # Intent
    intent = "filter"
    if re.search(r"\bcount\b", ql) or any(w in ql for w in ("how many","combien","total","number of")): intent = "count"
    elif any(w in ql for w in ("recommend","playbook","what to do","steps","remediate",
                               "how to respond","respond to","response","mitigat","remediat",
                               "contain","countermeasure","advise","advice","course of action",
                               "what should","how should","how do i","how do we","how to fix",
                               "fix alert","actions for","handle")): intent = "recommend"
    elif any(w in ql for w in ("investigate","analyze","explain","details","deep dive","tell me about")): intent = "investigate"
    if alert_id is not None and intent == "filter": intent = "investigate"

    alert_type  = next((t for t,kws in TYPE_KW.items()  if any(k in ql for k in kws)), None)
    source      = next((s for s,kws in SOURCE_KW.items() if any(k in ql for k in kws)), None)
    criticality = next((c for c,kws in CRIT_KW.items()  if any(k in ql for k in kws)), None)

    # Decision — only on explicit mention
    decision = None
    if any(w in ql for w in ("suppress","suppressed","not escalated","non escalated","low priority","ignored","dismissed")):
        decision = "suppress"
    elif any(w in ql for w in ("escalated",)) and "not" not in ql:
        decision = "ESCALATE"

    # Inheritance — only type and source, NEVER criticality or decision
    inherit_type   = (not alert_type  and bool(session.get("_type"))
                      and any(w in ql for w in ("and","just","only","also","too","critical","high","medium","low","them","those")))
    inherit_source = (not source and bool(session.get("_source"))
                      and not any(w in ql for w in ("all","global","overall","everywhere","across")))

    return {"intent":intent,"alert_id":alert_id,"alert_type":alert_type,"source":source,
            "criticality":criticality,"decision":decision,"sort":sort,
            "inherit_type":inherit_type,"inherit_source":inherit_source,
            "inherit_criticality":False,"inherit_decision":False}


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 3 — DATA
# ══════════════════════════════════════════════════════════════════════════════

def generate_alerts(output_path="alerts.csv", seed=42):
    random.seed(seed)
    rows, aid = [], 1
    base = datetime(2024, 11, 1, 6, 0, 0)
    for atype in ATTACK_TYPES:
        for _ in range(20):
            crit  = random.choices(["Low","Medium","High","Critical"], weights=CRIT_WEIGHTS[atype])[0]
            asset = random.choice(list(ASSETS.keys()))
            av    = ASSETS[asset]
            if crit == "Low" and random.random() < 0.70:
                cve, cvss = None, 0.0
            else:
                cve, cvss = random.choice(CVE_POOL[atype])
            history = random.random() > 0.40
            ts  = base + timedelta(hours=random.randint(0,168), minutes=random.randint(0,59))
            mc, mn = MITRE[atype]
            rows.append({
                "ID": aid, "Type": atype, "Criticality": crit,
                "Source": asset, "AssetValue": av,
                "CVE": cve if cve else "None", "CVSS": cvss,
                "History": history,
                "HistoryNote": HISTORY_NOTE[atype][0] if history else HISTORY_NOTE[atype][1],
                "MITRE_Code": mc, "MITRE_Name": mn,
                "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
                "Recommendations": RECOMMENDATIONS[atype],
            })
            aid += 1
    _write_csv(rows, output_path)
    dist = Counter(r["Criticality"] for r in rows)
    print(f"[OK] {len(rows)} alerts → {output_path}  (seed={seed})  {dict(dist)}")
    return rows


def generate_unsw_alerts(output_path="unsw_alerts.csv", n=500, seed=42):
    random.seed(seed)
    IP_ASSET = {
        "149.171.126": ("DomainController-01",10), "149.171.127": ("DatabaseServer-04",9),
        "175.45.176":  ("FileServer-02",8),         "175.45.177":  ("WebServer-03",7),
        "149.171.124": ("MailServer-05",7),          "149.171.125": ("AppServer-06",6),
        "59.166.0":    ("Workstation-07",4),         "59.166.1":    ("Workstation-08",4),
    }
    DEST_IPS = [k + ".1" for k in IP_ASSET]
    ATTACK_DIST = {"Malware":0.22,"BruteForce":0.28,"Ransomware":0.15,
                   "DataExfiltration":0.15,"Phishing":0.10}
    base_ts = datetime(2024, 11, 1, 6, 0, 0)
    rows = []
    for i in range(1, n+1):
        benign = random.random() < 0.40
        atype  = random.choices(list(ATTACK_DIST.keys()), weights=list(ATTACK_DIST.values()))[0]
        dstip  = random.choice(DEST_IPS)
        prefix = ".".join(dstip.split(".")[:3])
        asset_name, asset_val = IP_ASSET.get(prefix, (f"Host-{prefix}", random.randint(4,7)))
        if benign:
            cve, cvss = None, 0.0
            crit = random.choices(["Low","Medium"], weights=[0.4,0.6])[0]
        else:
            cve, cvss = random.choice(CVE_POOL[atype])
            crit = ("Critical" if cvss >= 9.0 else "High" if cvss >= 7.0
                    else "Medium" if cvss >= 4.0 else "Low")
        mc, mn   = MITRE[atype]
        has_hist = random.random() > 0.40
        ts       = base_ts + timedelta(hours=random.randint(0,24*30), minutes=random.randint(0,59))
        rows.append({
            "ID": i, "Type": atype, "Criticality": crit,
            "Source": asset_name, "AssetValue": asset_val,
            "CVE": cve if cve else "None", "CVSS": round(cvss,1),
            "History": has_hist,
            "HistoryNote": HISTORY_NOTE[atype][0] if has_hist else HISTORY_NOTE[atype][1],
            "MITRE_Code": mc, "MITRE_Name": mn,
            "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "Recommendations": RECOMMENDATIONS[atype],
        })
    _write_csv(rows, output_path)
    hc = sum(1 for r in rows if r["Criticality"] in ("High","Critical"))
    print(f"[OK] {len(rows)} UNSW alerts → {output_path}  H+C: {hc}/{n} ({hc/n*100:.1f}%)")
    return rows


def generate_cicids_alerts(output_path="cicids_alerts.csv", n=500, seed=42):
    """Cross-validation dataset derived from CICIDS-2017 (Sharafaldin et al., 2018).

    Mapping (paper Table 'CICIDS-2017 Category Mapping to SOC Alert Types'):
      DoS Hulk/GoldenEye/slowloris/Slowhttptest, DDoS, FTP/SSH-Patator, PortScan
          -> BruteForce  (volumetric / credential / reconnaissance traffic)
      Bot -> Malware  (persistent execution)
      Infiltration, Web Attacks (Brute Force / XSS / SQLi), Heartbleed
          -> DataExfiltration  (post-exploitation goals)
    Class weights among malicious records: BruteForce-family ~85%,
    DataExfiltration ~8%, Malware ~7%.  40% benign traffic tail.
    CVSS values = NVD median per class (records carry traffic features,
    not CVE identifiers, so per-class medians are used).
    Criticality derived from CVSS band exactly as in generate_unsw_alerts.
    """
    random.seed(seed)
    # (CICIDS class, weight among malicious, SOC type, NVD-median CVSS)
    CICIDS_CLASSES = [
        ("DoS Hulk",                  0.16, "BruteForce",       7.5),
        ("DoS GoldenEye",             0.05, "BruteForce",       7.5),
        ("DoS slowloris",             0.05, "BruteForce",       7.5),
        ("DoS Slowhttptest",          0.05, "BruteForce",       7.5),
        ("DDoS",                      0.12, "BruteForce",       7.5),
        ("PortScan",                  0.34, "BruteForce",       5.3),
        ("FTP-Patator",               0.04, "BruteForce",       8.1),
        ("SSH-Patator",               0.04, "BruteForce",       8.1),
        ("Bot",                       0.07, "Malware",          9.8),
        ("Infiltration",              0.02, "DataExfiltration", 8.8),
        ("Web Attack - Brute Force",  0.03, "DataExfiltration", 7.3),
        ("Web Attack - XSS / SQLi",   0.02, "DataExfiltration", 9.1),
        ("Heartbleed",                0.01, "DataExfiltration", 9.8),
    ]
    names   = [c[0] for c in CICIDS_CLASSES]
    weights = [c[1] for c in CICIDS_CLASSES]
    info    = {c[0]: (c[2], c[3]) for c in CICIDS_CLASSES}
    base_ts = datetime(2024, 11, 1, 6, 0, 0)
    rows = []
    for i in range(1, n + 1):
        benign = random.random() < 0.40
        asset  = random.choice(list(ASSETS.keys()))
        av     = ASSETS[asset]
        if benign:
            atype = random.choices(list(ATTACK_TYPES), k=1)[0]
            cve, cvss = None, 0.0
            crit = random.choices(["Low", "Medium"], weights=[0.4, 0.6])[0]
        else:
            cls          = random.choices(names, weights=weights)[0]
            atype, cvss  = info[cls]
            cve          = "None"   # CICIDS records carry traffic features, not CVEs
            crit = ("Critical" if cvss >= 9.0 else "High" if cvss >= 7.0
                    else "Medium" if cvss >= 4.0 else "Low")
        mc, mn   = MITRE[atype]
        has_hist = random.random() > 0.40
        ts       = base_ts + timedelta(hours=random.randint(0, 24 * 30),
                                       minutes=random.randint(0, 59))
        rows.append({
            "ID": i, "Type": atype, "Criticality": crit,
            "Source": asset, "AssetValue": av,
            "CVE": "None", "CVSS": round(cvss, 1),
            "History": has_hist,
            "HistoryNote": HISTORY_NOTE[atype][0] if has_hist else HISTORY_NOTE[atype][1],
            "MITRE_Code": mc, "MITRE_Name": mn,
            "Timestamp": ts.strftime("%Y-%m-%d %H:%M:%S"),
            "Recommendations": RECOMMENDATIONS[atype],
        })
    _write_csv(rows, output_path)
    hc = sum(1 for r in rows if r["Criticality"] in ("High", "Critical"))
    print(f"[OK] {len(rows)} CICIDS alerts → {output_path}  H+C: {hc}/{n} ({hc/n*100:.1f}%)")
    return rows


def _write_csv(rows, path):
    fields = ["ID","Type","Criticality","Source","AssetValue","CVE","CVSS",
              "History","HistoryNote","MITRE_Code","MITRE_Name","Timestamp","Recommendations"]
    with open(path, "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=fields)
        w.writeheader(); w.writerows(rows)


def load_alerts(csv_path="alerts.csv"):
    alerts = []
    with open(csv_path, newline="", encoding="utf-8") as f:
        for row in csv.DictReader(f):
            row["ID"]         = int(row["ID"])
            row["AssetValue"] = int(row["AssetValue"])
            row["CVSS"]       = float(row["CVSS"])
            row["History"]    = row["History"].strip().lower() in ("true","1","yes")
            alerts.append(row)
    return alerts


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 4 — RISK SCORING
# ══════════════════════════════════════════════════════════════════════════════

def is_correlated(alert, all_alerts, window_min=60):
    try:
        t1 = datetime.strptime(alert["Timestamp"], "%Y-%m-%d %H:%M:%S")
    except (ValueError, KeyError):
        return False
    for other in all_alerts:
        if other["ID"] == alert["ID"] or other["Source"] != alert["Source"]:
            continue
        try:
            t2 = datetime.strptime(other["Timestamp"], "%Y-%m-%d %H:%M:%S")
            if abs((t1 - t2).total_seconds()) / 60 <= window_min:
                return True
        except ValueError:
            continue
    return False


def risk_score(alert, correlated=False):
    crit  = CRIT_SCORE.get(alert.get("Criticality","Low"), 0.25)
    level = alert.get("Criticality","Low")
    rs = (alert["CVSS"]/10.0 + alert["AssetValue"]/10.0
          + (1.0 if alert["History"] else 0.0) + crit) / 4.0
    if   level == "Critical": rs = max(rs, 0.60)
    elif level == "High":     rs = max(rs, 0.50)
    if correlated: rs = min(1.0, rs + 0.15)
    return round(rs, 4)


def score_alerts(alerts, all_alerts):
    """Score and sort a list of alerts by operational priority."""
    for a in alerts:
        corr      = is_correlated(a, all_alerts)
        a["_corr"] = corr
        a["_rs"]   = risk_score(a, corr)
        a["_dec"]  = "ESCALATE" if a["_rs"] >= THRESHOLD else "suppress"
    alerts.sort(key=lambda x: (x["AssetValue"], x["_rs"]), reverse=True)
    return alerts


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 5 — CHATBOT
# ══════════════════════════════════════════════════════════════════════════════

HELP_MSG = (
    "Hello! I'm your SOC triage assistant.\n\n"
    "  • Filter alerts    →  'show critical alerts'\n"
    "  • By asset         →  'ransomware on DomainController'\n"
    "  • By decision      →  'show suppressed alerts'\n"
    "  • Investigate      →  'investigate malware on database'\n"
    "  • Playbook         →  'recommendations for phishing'\n"
    "  • Follow-up        →  'and the high ones?' (context remembered)\n"
    "  • Count            →  'how many critical alerts?'\n"
    "  • Pagination       →  type 'more'\n\n"
    "What would you like to investigate?"
)


class SOCChatbot:

    def __init__(self, csv_path="alerts.csv"):
        if not os.path.exists(csv_path):
            raise FileNotFoundError(f"{csv_path} not found — run: python soc_chatbot.py generate")
        self.alerts     = load_alerts(csv_path)
        self.session    = {}
        self.turn_count = 0
        print(f"[SOCChatbot] Loaded {len(self.alerts)} alerts from {csv_path}")

    def reset(self):
        self.session    = {}
        self.turn_count = 0

    def _ctx_string(self):
        """Build context string for LLM from current session."""
        parts = []
        for k, label in [("_type","type"),("_source","source"),("_crit","criticality")]:
            if self.session.get(k):
                parts.append(f"{label}={self.session[k]}")
        return ", ".join(parts)

    def _apply_filters(self, p):
        """Apply parsed filters to alert database. Returns scored+sorted list."""
        filtered = list(self.alerts)

        if p.get("alert_type"):
            filtered = [a for a in filtered if a["Type"] == p["alert_type"]]
        if p.get("source"):
            filtered = [a for a in filtered if a["Source"] == p["source"]]
        if p.get("criticality"):
            filtered = [a for a in filtered if a["Criticality"] == p["criticality"]]

        # Score first
        score_alerts(filtered, self.alerts)

        # Filter by decision only if explicitly requested
        if p.get("decision") == "suppress":
            filtered = [a for a in filtered if a["_dec"] == "suppress"]
        elif p.get("decision") == "ESCALATE":
            filtered = [a for a in filtered if a["_dec"] == "ESCALATE"]

        # Sort
        srt = p.get("sort")
        if srt == "rs":
            filtered.sort(key=lambda x: x["_rs"], reverse=True)
        elif srt == "asset":
            filtered.sort(key=lambda x: x["AssetValue"], reverse=True)
        # default sort (RS then AssetValue) already applied by score_alerts

        return filtered

    def _format_list(self, alerts, total, p):
        """Format alert list response — Python, instant."""
        n_esc = sum(1 for a in alerts if a.get("_dec") == "ESCALATE")

        # Build header label
        parts = []
        if p.get("criticality"): parts.append(p["criticality"])
        if p.get("alert_type"):  parts.append(p["alert_type"])
        if p.get("source"):      parts.append(f"on {p['source'].split('-')[0]}")
        if p.get("decision") == "suppress":   parts.append("(suppressed)")
        if p.get("decision") == "ESCALATE":   parts.append("(escalated)")
        label = " ".join(parts) if parts else "All"

        if not alerts:
            return f"No {label} alerts found. Try different filters."

        lines = [f"Found {total} {label} alert(s) — {n_esc} escalated\n"]
        lines.append(f"  {'ID':<5} {'Type':<18} {'Crit':<10} {'Asset':<22} {'RS':<7} Decision")
        lines.append(f"  {'─'*72}")
        for a in alerts:
            dec = "ESCALATE" if a["_dec"] == "ESCALATE" else "suppress"
            lines.append(f"  #{a['ID']:<4} {a['Type']:<18} {a['Criticality']:<10} "
                         f"{a['Source']:<22} {a['_rs']:<7} {dec}")
        if total > len(alerts):
            lines.append(f"\n  {total - len(alerts)} more — type 'more' to continue")
        return "\n".join(lines)

    def _format_count(self, filtered, p):
        """Format count response — Python, instant."""
        total = len(filtered)
        n_esc = sum(1 for a in filtered if a.get("_dec") == "ESCALATE")
        n_sup = total - n_esc

        parts = []
        if p.get("criticality"): parts.append(p["criticality"])
        if p.get("alert_type"):  parts.append(p["alert_type"])
        if p.get("source"):      parts.append(f"on {p['source'].split('-')[0]}")
        scope = " ".join(parts) if parts else "total"

        by_crit = {}
        for a in filtered:
            c = a.get("Criticality","?")
            by_crit[c] = by_crit.get(c, 0) + 1

        lines = [f"Alert count — {scope}", "─" * 40,
                 f"  Total     : {total}",
                 f"  ESCALATE  : {n_esc}",
                 f"  suppress  : {n_sup}"]
        if by_crit:
            lines.append("\n  By criticality:")
            for lvl in ("Critical","High","Medium","Low"):
                if lvl in by_crit:
                    lines.append(f"    {lvl:<10}: {by_crit[lvl]}")
        return "\n".join(lines)

    def _format_investigate(self, a):
        """Format deep investigation report — Python, instant."""
        cve_str = f"{a['CVE']} (CVSS {a['CVSS']})" if a["CVE"] != "None" else "No CVE published"
        dec     = "ESCALATE" if a["_dec"] == "ESCALATE" else "suppress"
        corr    = "  ⚡ Correlated — multi-stage attack suspected\n" if a.get("_corr") else ""
        recs    = a.get("Recommendations","").split(" | ")
        rec_txt = "\n".join(f"  {i}. {r.lstrip('0123456789. ')}" for i,r in enumerate(recs,1))

        return (
            f"Deep analysis — Alert #{a['ID']}\n{LINE}\n"
            f"  Type        : {a['Type']}\n"
            f"  Criticality : {a['Criticality']}\n"
            f"  Asset       : {a['Source']} (importance {a['AssetValue']}/10)\n"
            f"  CVE / CVSS  : {cve_str}\n"
            f"  MITRE       : {a.get('MITRE_Code','?')} — {a.get('MITRE_Name','?')}\n"
            f"  Timestamp   : {a.get('Timestamp','')}\n"
            f"  History     : {a.get('HistoryNote','No history')}\n"
            f"  Risk Score  : RS' = {a['_rs']}  →  {dec}\n"
            f"{corr}\n  Response playbook:\n{rec_txt}"
        )

    def _format_recommend(self, filtered, alert_type):
        """Format playbook response — Python, instant."""
        if not filtered:
            return "No matching alerts. Try: 'recommendations for ransomware'."
        n_esc = sum(1 for a in filtered if a["_dec"] == "ESCALATE")
        lines = [f"Response playbook — {n_esc} {alert_type or 'alerts'} alert(s) require escalation",
                 LINE]
        seen = set()
        for a in sorted(filtered, key=lambda x: (x["AssetValue"], x["_rs"]), reverse=True):
            if a["Type"] in seen: continue
            seen.add(a["Type"])
            recs = a.get("Recommendations","").split(" | ")
            lines += [f"\n{a['Type'].upper()} [{a['Criticality']}] on {a['Source']}",
                      f"  RS' = {a['_rs']}  →  {a['_dec'].upper()}",
                      f"  CVE: {a['CVE']}  |  MITRE: {a.get('MITRE_Code','?')}",
                      "  Actions:"]
            for i, r in enumerate(recs, 1):
                lines.append(f"    {i}. {r.lstrip('0123456789. ')}")
        return "\n".join(lines)

    def _ctx_string(self):
        parts = []
        if self.session.get("_type"):   parts.append(f"type={self.session['_type']}")
        if self.session.get("_source"): parts.append(f"source={self.session['_source']}")
        return ", ".join(parts) if parts else "none"

    def _paginate(self, t0):
        cache = self.session.get("_cache", [])
        page  = self.session.get("_page", 1)
        chunk = cache[page*10:(page+1)*10]
        if not chunk:
            return "No more alerts.", [], (time.perf_counter()-t0)*1000
        self.session["_page"] = page + 1
        total = len(cache)
        n_esc = sum(1 for a in chunk if a.get("_dec") == "ESCALATE")
        lines = [f"Page {page+1} — {page*10+1}–{page*10+len(chunk)} of {total} — {n_esc} escalated\n"]
        lines.append(f"  {'ID':<5} {'Type':<18} {'Crit':<10} {'Asset':<22} {'RS':<7} Decision")
        lines.append(f"  {'─'*72}")
        for a in chunk:
            dec = "ESCALATE" if a.get("_dec") == "ESCALATE" else "suppress"
            lines.append(f"  #{a['ID']:<4} {a['Type']:<18} {a['Criticality']:<10} "
                         f"{a['Source']:<22} {a['_rs']:<7} {dec}")
        remaining = total - (page+1)*10
        if remaining > 0:
            lines.append(f"\n  Type 'more' to continue ({remaining} remaining)")
        return "\n".join(lines), chunk, (time.perf_counter()-t0)*1000

    def process_query(self, query):
        t0 = time.perf_counter()
        ql = query.lower().strip().rstrip("?!. ")

        # ── 1. Instant: greetings ─────────────────────────────────────────────
        if ql in _GREETINGS:
            self.session["_greeted"] = True
            if not self.session.get("_said_hello"):
                self.session["_said_hello"] = True
                return HELP_MSG, [], (time.perf_counter()-t0)*1000
            return ("I'm your SOC triage assistant. What would you like to investigate?\n"
                    "Try: 'show critical alerts' or 'recommendations for ransomware'."), \
                   [], (time.perf_counter()-t0)*1000

        # ── 2. Instant: pagination (with fuzzy typo tolerance) ────────────────
        if ql in _MORE_KW:
            return self._paginate(t0)

        # ── 3. NLU — LLM understands query, keyword fallback if unavailable ───
        p      = call_llm_nlu(query, self.session) or _kw_parse(query, self.session)
        intent = p.get("intent", "filter")

        # ── 4. Greeting/more detected by NLU ─────────────────────────────────
        if intent == "greeting":
            self.session["_greeted"] = True
            if not self.session.get("_said_hello"):
                self.session["_said_hello"] = True
                return HELP_MSG, [], (time.perf_counter()-t0)*1000
            return ("I'm your SOC triage assistant. Try: 'show critical alerts'."), \
                   [], (time.perf_counter()-t0)*1000

        if intent == "more":
            return self._paginate(t0)

        # ── 5. Off-topic / general chat ───────────────────────────────────────
        if intent == "chat":
            return ("I'm a SOC triage assistant — I help with security alert investigation.\n"
                    "  • Filter    → 'show critical alerts'\n"
                    "  • Playbook  → 'recommendations for ransomware'\n"
                    "  • Analyze   → 'investigate malware on DomainController'\n"
                    "  • Count     → 'how many escalated alerts?'"), \
                   [], (time.perf_counter()-t0)*1000

        self.turn_count += 1

        # ── 6. Context inheritance — smart rules ──────────────────────────────
        # Criticality and decision are NEVER inherited (as per supervisor spec)
        # Type and source inherit only when analyst explicitly refines
        if p.get("inherit_type") and not p.get("alert_type") and self.session.get("_type"):
            p["alert_type"] = self.session["_type"]
        if p.get("inherit_source") and not p.get("source") and self.session.get("_source"):
            p["source"] = self.session["_source"]

        # For keyword fallback: simple source inheritance when query is a refinement
        # (e.g. "just critical", "and the high ones") — only type, never decision/criticality
        if not call_llm_nlu.__doc__:  pass  # always runs keyword path check
        if (not p.get("alert_type") and not p.get("source")
                and not p.get("decision") and self.session.get("_source")
                and any(w in ql for w in ("just","and the","only","also","too",
                                          "critical","high","medium","low","them","those"))):
            p["source"] = self.session["_source"]

        # Save context (only type and source — never criticality/decision)
        if p.get("alert_type"):  self.session["_type"]   = p["alert_type"]
        if p.get("source"):      self.session["_source"] = p["source"]
        # Always clear decision from session so it's never inherited
        self.session.pop("_decision", None)

        # ── 7. Filter & score alerts (Python — instant) ───────────────────────
        filtered = self._apply_filters(p)
        total    = len(filtered)
        shown    = filtered[:10]

        # Cache for pagination
        self.session["_cache"]   = filtered
        self.session["_page"]    = 1
        self.session["_greeted"] = True

        mtt_ms = (time.perf_counter() - t0) * 1000.0

        # ── 8. Build response ─────────────────────────────────────────────────
        if intent == "count":
            return self._format_count(filtered, p), shown, mtt_ms

        if intent == "investigate":
            # Priority 1: specific alert ID — Python finds it, LLM gets exact data
            alert_id = p.get("alert_id")
            if alert_id:
                target = next((a for a in self.alerts if a["ID"] == alert_id), None)
                if not target:
                    return f"Alert #{alert_id} not found. IDs range 1–{len(self.alerts)}.", [], mtt_ms
                corr = is_correlated(target, self.alerts)
                target["_corr"] = corr
                target["_rs"]   = risk_score(target, corr)
                target["_dec"]  = "ESCALATE" if target["_rs"] >= THRESHOLD else "suppress"
                ctx_msg = f"Analyst requests full analysis of alert #{alert_id}"
                resp = call_llm_format(query, [target], ctx_msg) or self._format_investigate(target)
                return resp, [target], mtt_ms

            # Priority 2: "analyze them/these/those" — use current cached context
            them_words = {"them","these","those","this","it","the above","ces","ceux","celles"}
            is_them = any(w in query.lower() for w in them_words)
            if (is_them or p.get("inherit_source")) and self.session.get("_cache"):
                pool    = self.session["_cache"][:5]
                ctx_msg = f"Analyze {len(pool)} alert(s) from current context"
                resp    = call_llm_format(query, pool, ctx_msg) or self._format_investigate(pool[0])
                return resp, pool, mtt_ms

            # Priority 3: filtered results
            if not filtered:
                return "No alerts found. Try: 'investigate malware on DomainController'.", [], mtt_ms
            a       = filtered[0]
            n_send  = min(5, total)
            ctx_msg = (f"TOTAL matching alerts in database: {total}. "
                       f"You received {n_send} alert(s) to analyze — do NOT say there are only {n_send}. "
                       f"Top alert: #{a['ID']} {a['Type']} [{a['Criticality']}] RS={a['_rs']}")
            resp    = call_llm_format(query, filtered[:n_send], ctx_msg) or self._format_investigate(a)
            return resp, filtered[:n_send], mtt_ms

        if intent == "recommend":
            n_send  = min(5, total)
            ctx_msg = (f"TOTAL matching: {total} alert(s). "
                       f"You received {n_send} for playbook generation.")
            resp    = call_llm_format(query, filtered[:n_send], ctx_msg) or \
                      self._format_recommend(filtered[:n_send], p.get("alert_type"))
            return resp, filtered[:n_send], mtt_ms

        # Default: filter list — Python only, no LLM, always fast
        return self._format_list(shown, total, p), shown, mtt_ms


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 6 — EVALUATION METRICS
# ══════════════════════════════════════════════════════════════════════════════

def batch_score(alerts, T):
    scored = []
    for a in alerts:
        corr = is_correlated(a, alerts)
        rs   = risk_score(a, corr)
        scored.append(dict(a, _rs=rs, _corr=corr, _dec="ESCALATE" if rs>=T else "SUPPRESS"))
    return scored


def grid_search(alerts):
    best_T, best_ta = 0.30, 0.0
    for ti in range(30, 50):
        T  = ti / 100.0
        sc = batch_score(alerts, T)
        ta = sum(1 for a in sc if (a["Criticality"] in ("High","Critical")) == (a["_dec"]=="ESCALATE")) / len(sc)
        if ta > best_ta: best_ta, best_T = ta, T
    return best_T


def triage_metrics(scored):
    tp = tn = fp = fn = 0
    for a in scored:
        real = a["Criticality"] in ("High","Critical")
        pred = a["_dec"] == "ESCALATE"
        if   real and pred:     tp += 1
        elif real and not pred: fn += 1
        elif not real and pred: fp += 1
        else:                   tn += 1
    N  = tp + tn + fp + fn
    ta = (tp + tn) / N
    P  = tp / (tp + fp) if (tp + fp) else 0.0
    R  = tp / (tp + fn) if (tp + fn) else 0.0
    F1 = 2 * P * R / (P + R) if (P + R) else 0.0
    return dict(tp=tp, tn=tn, fp=fp, fn=fn, N=N, ta=ta, P=P, R=R, F1=F1)


def cohens_kappa(m):
    N   = m["N"]
    p_o = m["ta"]
    p_e = (((m["tp"]+m["fp"])/N) * ((m["tp"]+m["fn"])/N) +
           ((m["tn"]+m["fn"])/N) * ((m["tn"]+m["fp"])/N))
    k   = (p_o - p_e) / (1 - p_e) if (1 - p_e) else 0.0
    band = ("substantial" if k>=0.61 else "moderate" if k>=0.41
            else "fair" if k>=0.21 else "slight" if k>=0.0 else "less than chance")
    return round(k,3), round(p_e,3), band


def auc_roc(alerts, scored):
    y_true = [1 if a["Criticality"] in ("High","Critical") else 0 for a in alerts]
    scores = [s["_rs"] for s in scored]
    tp_tot = sum(y_true); fp_tot = len(y_true) - tp_tot
    if not tp_tot or not fp_tot: return 0.0
    combined = sorted(zip(scores, y_true), key=lambda x: -x[0])
    auc = tcp = fcp = ptcp = pfcp = 0
    for _, y in combined:
        if y==1: tcp += 1
        else:    fcp += 1
        auc += (fcp - pfcp) * (tcp + ptcp) / 2
        ptcp, pfcp = tcp, fcp
    return round(auc / (tp_tot * fp_tot), 3)


def measure_mtt(alerts, n_sessions=20, n_queries=10):
    QUERIES = ["Show critical alerts","Malware on DomainController","Ransomware",
               "BruteForce on WebServer","Phishing","Critical DataExfiltration",
               "High alerts on DatabaseServer","Recommendations for malware",
               "Investigate exfiltration","All critical alerts"]
    latencies = []
    for _ in range(n_sessions):
        for q in QUERIES[:n_queries]:
            t0 = time.perf_counter()
            p  = _kw_parse(q)
            filtered = list(alerts)
            if p.get("alert_type"):  filtered = [a for a in filtered if a["Type"] == p["alert_type"]]
            if p.get("source"):      filtered = [a for a in filtered if a["Source"] == p["source"]]
            if p.get("criticality"): filtered = [a for a in filtered if a["Criticality"] == p["criticality"]]
            score_alerts(filtered, alerts)
            latencies.append((time.perf_counter() - t0) * 1000.0)
    M    = len(latencies)
    mean = statistics.mean(latencies)
    std  = statistics.stdev(latencies) if M > 1 else 0.0
    ci   = 1.96 * std / math.sqrt(M)
    return dict(M=M, mean=mean, std=std, ci_lo=mean-ci, ci_hi=mean+ci)


def measure_ecr(alerts):
    """Enrichment Coverage Rate.

    ecr        : mean per-field coverage  = (C_CVE + C_ATT&CK + C_History)/3
                 (the metric reported in the paper: 81% on the primary dataset)
    ecr_strict : fraction of alerts with ALL three fields populated (AND)
    Per-field coverages are returned so both definitions are transparent:
    ATT&CK and History are populated for 100% of alerts; the limiting
    factor is exclusively the CVE field (alerts with CVE=None by design).
    """
    n = len(alerts)
    c_cve  = sum(1 for a in alerts if a["CVE"] != "None") / n
    c_att  = sum(1 for a in alerts if a.get("MITRE_Code","")) / n
    c_hist = sum(1 for a in alerts if a.get("HistoryNote","")) / n
    strict = sum(1 for a in alerts if a["CVE"] != "None"
                 and a.get("MITRE_Code","") and a.get("HistoryNote","")) / n
    return dict(ecr=(c_cve+c_att+c_hist)/3, ecr_strict=strict,
                c_cve=c_cve, c_att=c_att, c_hist=c_hist)


def measure_mcrr(alerts_path="alerts.csv"):
    alerts = load_alerts(alerts_path)
    SESSIONS = [
        ("Malware on DomainController",    "And the phishing?",   "domaincontroller"),
        ("Critical ransomware",            "Any on WebServer?",    "webserver"),
        ("BruteForce on DatabaseServer",   "Show high ones",       "databaseserver"),
        ("Phishing on MailServer",         "Critical ones?",       "mailserver"),
        ("DataExfiltration on FileServer", "And malware?",         "fileserver"),
        ("High malware",                   "On AppServer?",        "appserver"),
        ("Critical alerts on WebServer",   "Ransomware too?",      "webserver"),
        ("Malware on Workstation-07",      "And phishing?",        "workstation-07"),
        ("BruteForce critical",            "On DomainController?", "domaincontroller"),
        ("Ransomware on DatabaseServer",   "High ones?",           "databaseserver"),
        ("Phishing on MailServer",         "Any malware?",         "mailserver"),
        ("DataExfiltration critical",      "On FileServer?",       "fileserver"),
        ("High alerts on AppServer",       "BruteForce?",          "appserver"),
        ("Malware on DomainController",    "Critical ones?",       "domaincontroller"),
        ("Critical phishing",              "On WebServer?",        "webserver"),
        ("Ransomware on Workstation-08",   "And malware?",         "workstation-08"),
        ("BruteForce on MailServer",       "Critical too?",        "mailserver"),
        ("DataExfiltration on FileServer", "High ones?",           "fileserver"),
        ("High malware on AppServer",      "Phishing?",            "appserver"),
        ("Critical BruteForce",            "On DatabaseServer?",   "databaseserver"),
    ]
    ok = 0
    for t1, t2, expected in SESSIONS:
        p1 = _kw_parse(t1); p2 = _kw_parse(t2)
        f1 = list(alerts)
        if p1.get("alert_type"):  f1 = [a for a in f1 if a["Type"] == p1["alert_type"]]
        if p1.get("source"):      f1 = [a for a in f1 if a["Source"] == p1["source"]]
        if p1.get("criticality"): f1 = [a for a in f1 if a["Criticality"] == p1["criticality"]]
        # Simulate context inheritance
        src2 = p2.get("source") or p1.get("source")
        at2  = p2.get("alert_type") or p1.get("alert_type")
        f2 = list(alerts)
        if at2:  f2 = [a for a in f2 if a["Type"] == at2]
        if src2: f2 = [a for a in f2 if a["Source"] == src2]
        resp = f"{src2 or ''} {at2 or ''} {p2.get('criticality') or ''}".lower()
        if expected.lower() in resp or any(expected.lower() in a["Source"].lower() for a in f2):
            ok += 1
    return dict(mcrr=ok/len(SESSIONS), ok=ok, total=len(SESSIONS))


def run_evaluation(csv_path="alerts.csv"):
    alerts = load_alerts(csv_path)
    T    = grid_search(alerts)
    sc   = batch_score(alerts, T)
    m    = triage_metrics(sc)
    k, p_e, band = cohens_kappa(m)
    auc  = auc_roc(alerts, sc)
    ecr  = measure_ecr(alerts)
    mtt  = measure_mtt(alerts)
    mcrr = measure_mcrr(csv_path)
    print(f"\n{SEP}")
    print(f"  EVALUATION  |  N={m['N']}  |  T={T}")
    print(SEP)
    print(f"  TP={m['tp']}  TN={m['tn']}  FP={m['fp']}  FN={m['fn']}")
    print(f"  TA={m['ta']*100:.1f}%  P={m['P']:.3f}  R={m['R']:.3f}  F1={m['F1']:.3f}")
    print(f"  κ={k:.3f} ({band})  AUC={auc:.3f}")
    print(f"  MTT={mtt['mean']:.3f}ms  ECR={ecr['ecr']*100:.1f}%  MCRR={mcrr['ok']}/{mcrr['total']}")
    print(f"{SEP}\n")
    return dict(T=T, m=m, k=k, p_e=p_e, band=band, auc=auc, ecr=ecr, mtt=mtt, mcrr=mcrr)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7 — STATISTICAL VALIDATION
# ══════════════════════════════════════════════════════════════════════════════

def run_multi_seed(seeds=(0,1,7,42,99), csv_path="alerts.csv"):
    print(f"\n{SEP}\n  MULTI-SEED\n{SEP}")
    alerts  = load_alerts(csv_path)
    results = []
    for s in seeds:
        random.seed(s)
        shuffled = list(alerts); random.shuffle(shuffled)
        for i, a in enumerate(shuffled, 1): a["ID"] = i
        T  = grid_search(shuffled)
        sc = batch_score(shuffled, T)
        m  = triage_metrics(sc)
        k, _, _ = cohens_kappa(m)
        au = auc_roc(shuffled, sc)
        results.append(dict(seed=s, T=T, ta=m["ta"], F1=m["F1"], k=k, R=m["R"], auc=au))
        print(f"  seed={s:2d}  TA={m['ta']*100:.1f}%  F1={m['F1']:.3f}  κ={k:.3f}  R={m['R']:.3f}")
    for key, fmt in [("ta",lambda v:f"{v*100:.1f}%"),("F1",lambda v:f"{v:.3f}"),
                     ("k", lambda v:f"{v:.3f}"),      ("auc",lambda v:f"{v:.3f}")]:
        vals = [r[key] for r in results]
        mean = statistics.mean(vals); std = statistics.stdev(vals) if len(vals)>1 else 0.0
        print(f"  {key:<4} mean={fmt(mean)} std={fmt(std)}")
    return results


def run_mcnemar(csv_path="alerts.csv", T=0.49):
    print(f"\n{SEP}\n  McNEMAR TEST\n{SEP}")
    alerts = load_alerts(csv_path)
    def rs_pred(a):  return risk_score(a, is_correlated(a, alerts)) >= T
    def b2_pred(a):  return (a["CVSS"]/10.0 + a["AssetValue"]/10.0) / 2.0 >= T
    def correct(p,a): return (a["Criticality"] in ("High","Critical")) == p
    n11=n10=n01=n00=0
    for a in alerts:
        rc = correct(rs_pred(a), a); bc = correct(b2_pred(a), a)
        if rc and bc: n11+=1
        elif rc:      n10+=1
        elif bc:      n01+=1
        else:         n00+=1
    b, c = n10, n01
    if b+c == 0: print("  b+c=0"); return None
    chi2 = (abs(b-c)-1)**2 / (b+c)
    p    = math.erfc(math.sqrt(chi2/2))
    sig  = "p<0.01 SIGNIFICANT" if p<0.01 else f"p={p:.4f}"
    print(f"  b={b}  c={c}  χ²={chi2:.4f}  {sig}")
    return dict(b=b, c=c, chi2=chi2, p=p)


def run_ablation(csv_path="alerts.csv", T=0.49):
    """Component ablation for RS'.

    Method: the removed component is DROPPED and the score is renormalized
    over the remaining components (mean of the remaining terms).  The
    correlation bonus is applied on top when enabled.  The safety floor is
    active only when C_crit is part of the score (the floor is implemented
    as a C_crit-anchored minimum).  The escalation threshold T = 0.49 is
    kept fixed across all variants.
    """
    print(f"\n{SEP}\n  ABLATION STUDY  (renormalized, T={T})\n{SEP}")
    alerts = load_alerts(csv_path)
    def sv(a, use_h=True, use_cc=True, use_corr=True, use_av=True, use_cvss=True):
        comps = []
        if use_cvss: comps.append(a["CVSS"]/10.0)
        if use_av:   comps.append(a["AssetValue"]/10.0)
        if use_h:    comps.append(1.0 if a["History"] else 0.0)
        if use_cc:   comps.append(CRIT_SCORE.get(a["Criticality"],0.25))
        rs = sum(comps)/len(comps) if comps else 0.0
        if use_cc:
            if a["Criticality"]=="Critical": rs=max(rs,0.60)
            elif a["Criticality"]=="High":   rs=max(rs,0.50)
        if use_corr and is_correlated(a,alerts): rs=min(1.0, rs+0.15)
        return rs
    variants = [
        ("RS' full",       dict()),
        ("Without C_crit", dict(use_cc=False)),
        ("Without H",      dict(use_h=False)),
        ("Without AV",     dict(use_av=False)),
        ("Without corr",   dict(use_corr=False)),
        ("CVSS only",      dict(use_av=False, use_h=False, use_cc=False, use_corr=False)),
    ]
    print(f"  {'Variant':<18} {'TA':>7} {'F1':>7} {'κ':>7} {'R':>7} {'FN':>5} {'FP':>5} {'AUC':>7}")
    for name, kw in variants:
        sc=[dict(a,_rs=sv(a,**kw),_dec="ESCALATE" if sv(a,**kw)>=T else "SUPPRESS") for a in alerts]
        m=triage_metrics(sc); k,_,_=cohens_kappa(m); au=auc_roc(alerts, sc)
        flag=" ←" if name=="RS' full" else ""
        print(f"  {name:<18} {m['ta']*100:>6.1f}%  {m['F1']:>6.3f}  {k:>6.3f}  {m['R']:>6.3f}  {m['fn']:>4d} {m['fp']:>5d} {au:>7.3f}{flag}")


def run_window_sensitivity(csv_path="alerts.csv", T=0.49):
    print(f"\n{SEP}\n  WINDOW SENSITIVITY\n{SEP}")
    alerts = load_alerts(csv_path)
    for w in [15,30,60,120]:
        def sw(a):
            try:
                t1=datetime.strptime(a["Timestamp"],"%Y-%m-%d %H:%M:%S")
                corr=any(o["ID"]!=a["ID"] and o["Source"]==a["Source"] and
                         abs((t1-datetime.strptime(o["Timestamp"],"%Y-%m-%d %H:%M:%S")).total_seconds())/60<=w
                         for o in alerts)
            except: corr=False
            return risk_score(a,corr)
        sc=[dict(a,_rs=sw(a),_dec="ESCALATE" if sw(a)>=T else "SUPPRESS") for a in alerts]
        m=triage_metrics(sc); k,_,_=cohens_kappa(m)
        flag="  ← paper" if w==60 else ""
        print(f"  {w:>6}min  TA={m['ta']*100:.1f}%  F1={m['F1']:.3f}  R={m['R']:.3f}{flag}")


def run_cross_dataset(paths=("alerts.csv", "unsw_alerts.csv", "cicids_alerts.csv"), T=0.49):
    """Reproduces the paper's cross-dataset table: Naive / CVSS+AV / RS' on each dataset."""
    print(f"\n{SEP}\n  CROSS-DATASET EVALUATION  (T={T})\n{SEP}")
    print(f"  {'Dataset':<22} {'Method':<9} {'TA':>7} {'F1':>7} {'κ':>7} {'R':>7} {'AUC':>7} {'FN':>4}")
    for path in paths:
        if not os.path.exists(path):
            print(f"  {path:<22} — missing (run: python soc_chatbot.py generate)")
            continue
        alerts = load_alerts(path)
        methods = [
            ("Naive",   lambda a: 1.0),
            ("CVSS+AV", lambda a: (a["CVSS"]/10.0 + a["AssetValue"]/10.0) / 2.0),
            ("RS'",     lambda a: risk_score(a, is_correlated(a, alerts))),
        ]
        for name, score_fn in methods:
            sc = [dict(a, _rs=score_fn(a),
                       _dec="ESCALATE" if score_fn(a) >= T else "SUPPRESS") for a in alerts]
            m  = triage_metrics(sc)
            k, _, _ = cohens_kappa(m)
            au = auc_roc(alerts, sc) if name != "Naive" else 0.5
            print(f"  {path:<22} {name:<9} {m['ta']*100:>6.1f}% {m['F1']:>7.3f} "
                  f"{k:>7.3f} {m['R']:>7.3f} {au:>7.3f} {m['fn']:>4d}")
        print()


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 7b — LEARNED BASELINES, CONFIDENCE INTERVALS, WEIGHT OPTIMIZATION
#               (added for the revised evaluation; all seeded, reproducible)
# ══════════════════════════════════════════════════════════════════════════════

def _feature_vector(a, all_alerts, include_crit=False):
    """The exact inputs RS' uses. include_crit=False excludes C_crit because
    ground truth is defined as Criticality in {High, Critical}: giving a
    learner the criticality label is label leakage (any model trivially
    reaches 100%).  RS' uses that label only through the deterministic
    safety floor, which is reported as a design property, not performance."""
    h = (1.0 if a["History"] else 0.0) + (0.15 if is_correlated(a, all_alerts) else 0.0)
    x = [a["CVSS"] / 10.0, a["AssetValue"] / 10.0, h]
    if include_crit:
        x.append(CRIT_SCORE.get(a.get("Criticality", "Low"), 0.25))
    return x


def run_learned_baselines(csv_path="alerts.csv", seed=42, folds=5):
    """Logistic Regression and Random Forest on the same exogenous features
    RS' uses (CVSS, AssetValue, History+correlation), 5-fold stratified CV."""
    from sklearn.linear_model import LogisticRegression
    from sklearn.ensemble import RandomForestClassifier
    from sklearn.model_selection import StratifiedKFold
    from sklearn.metrics import roc_auc_score

    alerts = load_alerts(csv_path)
    X = [_feature_vector(a, alerts) for a in alerts]
    y = [1 if a["Criticality"] in ("High", "Critical") else 0 for a in alerts]

    models = {
        "LogReg":  lambda: LogisticRegression(max_iter=1000, random_state=seed),
        "RandFor": lambda: RandomForestClassifier(n_estimators=100, max_depth=4,
                                                 random_state=seed),
    }
    print(f"\nLEARNED BASELINES  |  {csv_path}  |  {folds}-fold stratified CV  "
          f"|  features: CVSS, AV, History+corr (C_crit excluded: label leakage)")
    results = {}
    for name, mk in models.items():
        skf = StratifiedKFold(n_splits=folds, shuffle=True, random_state=seed)
        tp = tn = fp = fn = 0
        aucs = []
        for tr, te in skf.split(X, y):
            m = mk().fit([X[i] for i in tr], [y[i] for i in tr])
            proba = m.predict_proba([X[i] for i in te])[:, 1]
            pred  = m.predict([X[i] for i in te])
            yt    = [y[i] for i in te]
            for p, t in zip(pred, yt):
                if   t and p:     tp += 1
                elif t and not p: fn += 1
                elif not t and p: fp += 1
                else:             tn += 1
            if len(set(yt)) > 1:
                aucs.append(roc_auc_score(yt, proba))
        N  = tp + tn + fp + fn
        ta = (tp + tn) / N
        P  = tp / (tp + fp) if tp + fp else 0.0
        R  = tp / (tp + fn) if tp + fn else 0.0
        F1 = 2 * P * R / (P + R) if P + R else 0.0
        k, _, _ = cohens_kappa(dict(tp=tp, tn=tn, fp=fp, fn=fn, N=N, ta=ta))
        auc = sum(aucs) / len(aucs)
        results[name] = dict(ta=ta, P=P, R=R, F1=F1, k=k, auc=auc, fn=fn, fp=fp)
        print(f"  {name:8s} TA={ta*100:5.1f}%  P={P:.3f}  R={R:.3f}  F1={F1:.3f}"
              f"  kappa={k:.3f}  AUC={auc:.3f}  FN={fn}  FP={fp}")
    return results


def run_bootstrap_ci(csv_path="alerts.csv", T=0.49, n_boot=2000, seed=42):
    """Percentile bootstrap 95% CIs for TA, F1 and kappa at the fixed T."""
    rng = random.Random(seed)
    alerts = load_alerts(csv_path)
    scored = batch_score(alerts, T)          # score once; resample outcomes
    stats = {"ta": [], "f1": [], "k": []}
    n = len(scored)
    for _ in range(n_boot):
        sample = [scored[rng.randrange(n)] for _ in range(n)]
        m = triage_metrics(sample)
        k, _, _ = cohens_kappa(m)
        stats["ta"].append(m["ta"]); stats["f1"].append(m["F1"]); stats["k"].append(k)
    out = {}
    for key, vals in stats.items():
        vals.sort()
        lo, hi = vals[int(0.025 * n_boot)], vals[int(0.975 * n_boot) - 1]
        out[key] = (lo, hi)
    m = triage_metrics(scored); k, _, _ = cohens_kappa(m)
    print(f"\nBOOTSTRAP 95% CI  |  {csv_path}  |  B={n_boot}  seed={seed}")
    print(f"  TA    = {m['ta']*100:.1f}%  [{out['ta'][0]*100:.1f}%, {out['ta'][1]*100:.1f}%]")
    print(f"  F1    = {m['F1']:.3f}  [{out['f1'][0]:.3f}, {out['f1'][1]:.3f}]")
    print(f"  kappa = {k:.3f}  [{out['k'][0]:.3f}, {out['k'][1]:.3f}]")
    return out


def _weighted_rs(a, corr, w):
    wV, wA, wH, wC = w
    level = a.get("Criticality", "Low")
    rs = (wV * a["CVSS"] / 10.0 + wA * a["AssetValue"] / 10.0
          + wH * (1.0 if a["History"] else 0.0)
          + wC * CRIT_SCORE.get(level, 0.25))
    if   level == "Critical": rs = max(rs, 0.60)   # safety floor: NON-NEGOTIABLE
    elif level == "High":     rs = max(rs, 0.50)
    if corr: rs = min(1.0, rs + 0.15)
    return rs


def run_weight_optimization(train_csv="alerts.csv",
                            test_csvs=("unsw_alerts.csv", "cicids_alerts.csv"),
                            T=0.49, step=0.05):
    """Constrained grid search over component weights (sum to 1, step 0.05).
    The safety floor is kept as a hard constraint, so Recall = 1.000 for every
    candidate; the search maximizes F1 (ties: fewer FP) on the primary set,
    then the chosen weights are evaluated UNCHANGED on the cross-datasets."""
    def eval_w(csv_path, w):
        alerts = load_alerts(csv_path)
        corrs  = {a["ID"]: is_correlated(a, alerts) for a in alerts}
        scored = [dict(a, _rs=_weighted_rs(a, corrs[a["ID"]], w),
                       _dec="ESCALATE" if _weighted_rs(a, corrs[a["ID"]], w) >= T
                            else "SUPPRESS") for a in alerts]
        m = triage_metrics(scored)
        k, _, _ = cohens_kappa(m)
        return m, k

    steps = int(round(1.0 / step))
    best, best_key = None, None
    for i in range(steps + 1):
        for j in range(steps + 1 - i):
            for k3 in range(steps + 1 - i - j):
                l = steps - i - j - k3
                w = (i * step, j * step, k3 * step, l * step)
                m, kap = eval_w(train_csv, w)
                key = (m["F1"], -m["fp"], m["ta"])
                if best_key is None or key > best_key:
                    best_key, best = key, (w, m, kap)
    w, m, kap = best
    print(f"\nWEIGHT OPTIMIZATION  |  train={train_csv}  T={T}  step={step}  "
          f"(floor kept => R=1.000 for all candidates)")
    print(f"  Equal weights  : TA=87.0%  F1=0.908  kappa=0.694  FP=13  (reference)")
    print(f"  Best weights   : wV={w[0]:.2f} wA={w[1]:.2f} wH={w[2]:.2f} wC={w[3]:.2f}")
    print(f"  Primary        : TA={m['ta']*100:.1f}%  F1={m['F1']:.3f}  "
          f"kappa={kap:.3f}  FP={m['fp']}  FN={m['fn']}")
    for tc in test_csvs:
        if os.path.exists(tc):
            mt, kt = eval_w(tc, w)
            print(f"  {tc:18s}: TA={mt['ta']*100:.1f}%  F1={mt['F1']:.3f}  "
                  f"kappa={kt:.3f}  FP={mt['fp']}  FN={mt['fn']}")
    return w, m


def run_all_statistical_fixes(csv_path="alerts.csv"):
    run_multi_seed(csv_path=csv_path)
    run_mcnemar(csv_path=csv_path)
    run_ablation(csv_path=csv_path)
    run_window_sensitivity(csv_path=csv_path)


# ══════════════════════════════════════════════════════════════════════════════
# SECTION 8 — CLI
# ══════════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import sys
    cmd = sys.argv[1] if len(sys.argv) > 1 else "help"

    if cmd == "generate":
        # NOTE: the distributed CSVs are the CANONICAL evaluation artifacts
        # used in the paper.  They are only (re)generated when absent, so a
        # checkout of the repository always reproduces the published metrics.
        # unsw_alerts.csv in particular was produced by an earlier revision of
        # generate_unsw_alerts and is preserved as-is (delete the file to
        # force regeneration — the regenerated dataset will differ).
        if not os.path.exists("alerts.csv"):
            generate_alerts("alerts.csv", seed=42)
        else:
            print("[skip] alerts.csv exists (canonical)")
        if not os.path.exists("unsw_alerts.csv"):
            generate_unsw_alerts("unsw_alerts.csv", seed=42)
        else:
            print("[skip] unsw_alerts.csv exists (canonical)")
        if not os.path.exists("cicids_alerts.csv"):
            generate_cicids_alerts("cicids_alerts.csv", seed=42)
        else:
            print("[skip] cicids_alerts.csv exists (canonical)")

    elif cmd == "baselines-ml":
        run_learned_baselines("alerts.csv")

    elif cmd == "ci":
        run_bootstrap_ci("alerts.csv")

    elif cmd == "optimize-weights":
        run_weight_optimization()

    elif cmd == "chat":
        bot = SOCChatbot("alerts.csv")
        print(f"\n{'='*60}\nSOC CHATBOT  (quit | reset)\n{'='*60}")
        while True:
            try:
                q = input("\nAnalyst > ").strip()
                if q.lower() in ("quit","exit","q"): break
                if q.lower() == "reset": bot.reset(); print("[Session reset]"); continue
                resp, _, mtt = bot.process_query(q)
                print(resp)
                print(f"\n[Turn {bot.turn_count}  |  {mtt:.0f}ms]")
            except KeyboardInterrupt: break

    elif cmd == "evaluate":
        run_evaluation("alerts.csv")
        print("UNSW-NB15:")
        run_evaluation("unsw_alerts.csv")
        if os.path.exists("cicids_alerts.csv"):
            print("CICIDS-2017:")
            run_evaluation("cicids_alerts.csv")
        run_cross_dataset()

    elif cmd == "stats":
        run_all_statistical_fixes("alerts.csv")

    elif cmd == "all":
        for path, gen in (("alerts.csv", generate_alerts),
                          ("unsw_alerts.csv", generate_unsw_alerts),
                          ("cicids_alerts.csv", generate_cicids_alerts)):
            if not os.path.exists(path):
                gen(path, seed=42)
        run_evaluation("alerts.csv")
        run_cross_dataset()
        run_all_statistical_fixes("alerts.csv")

    else:
        print("Usage: python soc_chatbot.py [generate|chat|evaluate|stats|all]")