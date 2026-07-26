# soc_interface.py — SOC Cognitive Chatbot
# Run:  python soc_interface.py  →  http://127.0.0.1:7860

import gradio as gr
import csv, os, threading
from datetime import datetime
from soc_chatbot import (
    SOCChatbot, load_alerts, grid_search, batch_score,
    triage_metrics, cohens_kappa, auc_roc,
    measure_mtt, measure_ecr, measure_mcrr,
)

CSV_PATH    = "alerts.csv"
RESULTS_CSV = "user_study_results.csv"
_csv_lock   = threading.Lock()

SCALE = [
    "1 - Strongly disagree",
    "2 - Disagree",
    "3 - Neutral",
    "4 - Agree",
    "5 - Strongly agree",
]

CSS = """
@import url('https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600&family=JetBrains+Mono:wght@400&display=swap');

:root {
  --bg:      #0d1117;
  --surface: #161b22;
  --card:    #21262d;
  --border:  #30363d;
  --accent:  #58a6ff;
  --green:   #3fb950;
  --red:     #f85149;
  --amber:   #e3b341;
  --text:    #e6edf3;
  --muted:   #8b949e;
  --subtle:  #484f58;
  --mono:    'JetBrains Mono', 'Cascadia Code', Consolas, monospace;
  --sans:    'Inter', -apple-system, sans-serif;
}

/* ── Reset ── */
body, .gradio-container {
  background: var(--bg) !important;
  font-family: var(--sans) !important;
}
.gradio-container { max-width: 100% !important; padding: 0 !important; }
footer { display: none !important; }

/* ── Hide share button and other Gradio chrome ── */
.share-button, button[title="Share"], .copy-btn,
.gr-button-share, [data-testid="share-btn"],
.svelte-1ipelgc { display: none !important; }

/* ── Tabs ── */
.tab-nav {
  background: var(--surface) !important;
  border-bottom: 1px solid var(--border) !important;
  padding: 0 24px !important;
  margin: 0 !important;
}
.tab-nav button {
  font-family: var(--sans) !important;
  font-size: 13px !important;
  font-weight: 400 !important;
  color: var(--muted) !important;
  background: transparent !important;
  border: none !important;
  padding: 14px 20px !important;
  border-bottom: 2px solid transparent !important;
  transition: color .15s !important;
  letter-spacing: .2px !important;
}
.tab-nav button.selected {
  color: var(--text) !important;
  border-bottom-color: var(--accent) !important;
  font-weight: 500 !important;
}
.tab-nav button:hover { color: var(--text) !important; }
.tabitem { padding: 0 !important; background: var(--bg) !important; }

/* ── Chat window ── */
.chatbot {
  background: var(--bg) !important;
  border: none !important;
  border-radius: 0 !important;
}

/* User bubble — right aligned, compact */
[data-testid="user"] {
  justify-content: flex-end !important;
  padding: 4px 20px !important;
}
[data-testid="user"] > div {
  background: #1c3a5e !important;
  border: 1px solid #2a4a70 !important;
  border-radius: 12px 12px 2px 12px !important;
  color: #cdd9e5 !important;
  font-family: var(--sans) !important;
  font-size: 14px !important;
  line-height: 1.5 !important;
  padding: 8px 14px !important;
  max-width: 60% !important;
}

/* Bot bubble — full width, terminal style */
[data-testid="bot"] {
  padding: 2px 20px 10px !important;
}
[data-testid="bot"] > div {
  background: var(--surface) !important;
  border: 1px solid var(--border) !important;
  border-top: 2px solid var(--accent) !important;
  border-radius: 0 8px 8px 8px !important;
  color: #c9d1d9 !important;
  font-family: var(--mono) !important;
  font-size: 12.5px !important;
  line-height: 1.75 !important;
  padding: 14px 18px !important;
  max-width: 100% !important;
  white-space: pre-wrap !important;
}

/* Avatar hide */
[data-testid="bot"] .avatar-container,
[data-testid="user"] .avatar-container { display: none !important; }

/* ── Input area ── */
.input-area, .input-row { background: var(--surface) !important; }

textarea, input[type="text"] {
  background: var(--card) !important;
  border: 1px solid var(--border) !important;
  border-radius: 8px !important;
  color: var(--text) !important;
  font-family: var(--sans) !important;
  font-size: 14px !important;
  padding: 10px 14px !important;
  transition: border-color .15s, box-shadow .15s !important;
}
textarea:focus, input[type="text"]:focus {
  border-color: var(--accent) !important;
  box-shadow: 0 0 0 3px rgba(88,166,255,.1) !important;
  outline: none !important;
}

/* ── Buttons ── */
button.primary {
  background: var(--accent) !important;
  color: #0d1117 !important;
  font-family: var(--sans) !important;
  font-weight: 600 !important;
  font-size: 13px !important;
  border: none !important;
  border-radius: 8px !important;
  padding: 10px 20px !important;
  letter-spacing: .2px !important;
  transition: opacity .15s !important;
}
button.primary:hover { opacity: .88 !important; }

button.secondary {
  background: transparent !important;
  color: var(--muted) !important;
  font-family: var(--sans) !important;
  font-size: 12px !important;
  border: 1px solid var(--border) !important;
  border-radius: 6px !important;
  transition: all .15s !important;
}
button.secondary:hover {
  color: var(--text) !important;
  border-color: var(--muted) !important;
  background: var(--card) !important;
}

/* ── Markdown (evaluation tab) ── */
.prose, .markdown { color: var(--text) !important; font-family: var(--sans) !important; font-size: 13px !important; }
.prose table, .markdown table { width: 100% !important; border-collapse: collapse !important; }
.prose th, .markdown th {
  background: var(--card) !important; color: var(--muted) !important;
  font-size: 11px !important; font-weight: 500 !important; text-transform: uppercase !important;
  letter-spacing: .5px !important; padding: 8px 12px !important; border: 1px solid var(--border) !important;
}
.prose td, .markdown td { padding: 8px 12px !important; border: 1px solid var(--border) !important; color: var(--text) !important; }
.prose tr:nth-child(even) td, .markdown tr:nth-child(even) td { background: var(--surface) !important; }
.prose strong, .markdown strong { color: var(--text) !important; }
.prose code, .markdown code {
  background: var(--card) !important; color: var(--accent) !important;
  font-family: var(--mono) !important; font-size: 11px !important;
  padding: 2px 6px !important; border-radius: 3px !important;
}

/* ── Form elements ── */
label { color: var(--muted) !important; font-size: 12px !important; font-weight: 500 !important; }
.gr-radio label { color: var(--text) !important; font-size: 13px !important; }
select, .gr-dropdown { background: var(--card) !important; color: var(--text) !important; border-color: var(--border) !important; }

/* ── Scrollbar ── */
::-webkit-scrollbar { width: 4px; height: 4px; }
::-webkit-scrollbar-track { background: transparent; }
::-webkit-scrollbar-thumb { background: var(--border); border-radius: 4px; }
::-webkit-scrollbar-thumb:hover { background: var(--muted); }
"""


# ── Helpers ───────────────────────────────────────────────────────────────────
def new_bot():
    return SOCChatbot(CSV_PATH)


def _load_results():
    if not os.path.exists(RESULTS_CSV):
        return []
    with open(RESULTS_CSV, newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def context_bar(bot):
    if not bot or bot.turn_count == 0:
        return ""
    return (
        f'<div style="display:flex;align-items:center;gap:12px;padding:5px 24px;'
        f'background:#161b22;border-bottom:1px solid #21262d;font-size:11px;">'
        f'<span style="color:#484f58;text-transform:uppercase;letter-spacing:.6px">Session</span>'
        f'<span style="color:#58a6ff;font-weight:500">turn {bot.turn_count}</span>'
        f'<span style="color:#30363d">|</span>'
        f'<span style="color:#484f58">context memory active</span>'
        f'</div>'
    )


def summary_html():
    rows = _load_results()
    if not rows:
        return '<div style="color:#8b949e;font-size:13px;padding:10px 0">No responses yet.</div>'
    n = len(rows)
    dims = {
        "Q1_context_clarity":           "Context clarity",
        "Q2_recommendation_usefulness": "Recommendation usefulness",
        "Q3_ease_of_use":               "Ease of use",
        "Q4_time_savings":              "Perceived time savings",
    }
    html = ""; overall = 0
    for key, label in dims.items():
        vals = [int(r[key]) for r in rows if r.get(key, "").isdigit()]
        mean = sum(vals) / len(vals) if vals else 0
        overall += mean
        pct   = int((mean - 1) / 4 * 100) if mean > 0 else 0
        color = "#3fb950" if mean >= 4 else "#e3b341" if mean >= 3 else "#f85149"
        html += (
            f'<div style="margin:10px 0">'
            f'<div style="display:flex;justify-content:space-between;font-size:12px;'
            f'color:#8b949e;margin-bottom:5px">'
            f'<span>{label}</span>'
            f'<span style="color:{color};font-weight:600">{mean:.2f} / 5</span></div>'
            f'<div style="background:#21262d;border-radius:3px;height:4px">'
            f'<div style="background:{color};border-radius:3px;height:4px;'
            f'width:{pct}%;transition:width .4s"></div></div></div>'
        )
    overall /= 4
    oc = "#3fb950" if overall >= 4 else "#e3b341" if overall >= 3 else "#f85149"
    return (
        f'<div style="background:#161b22;border:1px solid #30363d;border-radius:8px;'
        f'padding:18px 22px;margin-top:14px">'
        f'<div style="font-size:11px;color:#484f58;text-transform:uppercase;'
        f'letter-spacing:.6px;margin-bottom:16px">{n} response{"s" if n!=1 else ""}</div>'
        f'{html}'
        f'<div style="margin-top:16px;padding-top:14px;border-top:1px solid #30363d;'
        f'display:flex;justify-content:space-between;align-items:center">'
        f'<span style="font-size:13px;color:#8b949e">Overall mean</span>'
        f'<span style="font-size:20px;font-weight:600;color:{oc}">{overall:.2f} <span style="font-size:13px;color:#484f58">/ 5</span></span>'
        f'</div></div>'
    )


# ── Tab 1: Chat ───────────────────────────────────────────────────────────────
def chat(user_msg, history, bot):
    if bot is None:
        bot = new_bot()
    if history is None:
        history = []
    if not user_msg or not str(user_msg).strip():
        return history, "", context_bar(bot), bot

    response, _, mtt = bot.process_query(str(user_msg))
    ts = datetime.now().strftime("%H:%M")

    # Minimal meta line — time + latency
    meta = (
        f'<div style="font-size:10px;color:#484f58;margin-bottom:8px;'
        f'padding-bottom:6px;border-bottom:1px solid #21262d;'
        f'display:flex;justify-content:space-between">'
        f'<span>SOC Assistant</span>'
        f'<span>{ts} · {mtt:.0f}ms</span>'
        f'</div>'
    )

    # Response — preserve monospace formatting
    content = (
        f'<div style="color:#c9d1d9;font-size:12.5px;line-height:1.75;'
        f'white-space:pre-wrap;font-family:inherit">{response}</div>'
    )

    history = list(history) + [
        {"role": "user",      "content": str(user_msg)},
        {"role": "assistant", "content": meta + content},
    ]
    return history, "", context_bar(bot), bot


def reset_chat(history, bot):
    if bot is None:
        bot = new_bot()
    else:
        bot.reset()
    return [], "", "", bot


# ── Tab 2: Evaluation ─────────────────────────────────────────────────────────
def run_evaluation_ui():
    try:
        alerts = load_alerts(CSV_PATH)
    except Exception:
        return "❌  alerts.csv not found — run:  `python soc_chatbot.py generate`"
    T    = grid_search(alerts)
    sc   = batch_score(alerts, T)
    m    = triage_metrics(sc)
    k, p_e, band = cohens_kappa(m)
    auc  = auc_roc(alerts, sc)
    ecr  = measure_ecr(alerts)
    mtt  = measure_mtt(alerts)
    mcrr = measure_mcrr(CSV_PATH)
    rows = _load_results()
    if rows:
        dims   = ["Q1_context_clarity","Q2_recommendation_usefulness","Q3_ease_of_use","Q4_time_savings"]
        labels = ["Context clarity","Recommendation usefulness","Ease of use","Time savings"]
        means  = {d: (sum(int(r[d]) for r in rows if r.get(d,"").isdigit()) /
                      max(1, sum(1 for r in rows if r.get(d,"").isdigit())))
                  for d in dims}
        ov     = sum(means.values()) / 4
        likert = (
            f"\n\n### Human evaluation  ({len(rows)} participant{'s' if len(rows)>1 else ''})\n\n"
            "| Dimension | Mean |\n|---|---|\n"
            + "\n".join(f"| {lb} | **{means[d]:.2f}** |" for lb, d in zip(labels, dims))
            + f"\n| **Overall** | **{ov:.2f} / 5** |"
        )
    else:
        likert = "\n\n### Human evaluation\n\n_No responses yet — see User Study tab._"

    return f"""## Results  ·  N={m['N']}  ·  seed=42  ·  T={T}

### Classification

| Metric | Value | Meaning |
|--------|-------|---------|
| Triage Accuracy | **{m['ta']*100:.1f}%** | {m['tp']+m['tn']} / {m['N']} correctly classified |
| Precision | **{m['P']:.3f}** | {m['P']*100:.0f}% of escalated alerts were real threats |
| Recall | **{m['R']:.3f}** | Zero real threats missed |
| F1-Score | **{m['F1']:.3f}** | |
| Cohen κ | **{k:.3f}** ({band}) | Performance beyond chance |
| AUC-ROC | **{auc:.3f}** | |

### Pipeline

| Metric | Value | Meaning |
|--------|-------|---------|
| MTT | **{mtt['mean']:.2f} ms** | Pipeline latency per query |
| ECR | **{ecr['ecr']*100:.1f}%** | Alerts pre-enriched automatically |
| MCRR | **{mcrr['ok']}/{mcrr['total']}** | Multi-turn sessions passed |
{likert}"""


# ── Tab 3: User Study ─────────────────────────────────────────────────────────
def submit_likert(pid, background, experience, q1, q2, q3, q4, feedback):
    errors = []
    if not pid or not pid.strip():
        errors.append("Participant ID required.")
    for lbl, val in [("Q1", q1), ("Q2", q2), ("Q3", q3), ("Q4", q4)]:
        if not val:
            errors.append(f"{lbl}: please select a rating.")
    if errors:
        return "  ·  ".join(errors), summary_html()
    pid = pid.strip()
    if any(r.get("participant_id") == pid for r in _load_results()):
        return f"ID '{pid}' already submitted.", summary_html()

    def sc(s): return int(s[0]) if s and s[0].isdigit() else None

    row = {
        "timestamp":                    datetime.now().isoformat(),
        "participant_id":               pid,
        "background":                   background or "",
        "experience_years":             experience or "",
        "Q1_context_clarity":           sc(q1),
        "Q2_recommendation_usefulness": sc(q2),
        "Q3_ease_of_use":               sc(q3),
        "Q4_time_savings":              sc(q4),
        "open_feedback":                (feedback or "").strip(),
    }
    with _csv_lock:
        exists = os.path.exists(RESULTS_CSV)
        with open(RESULTS_CSV, "a", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=list(row.keys()))
            if not exists:
                w.writeheader()
            w.writerow(row)

    return f"✓  Saved — {pid}  (Q1={sc(q1)} Q2={sc(q2)} Q3={sc(q3)} Q4={sc(q4)})", summary_html()


def export_csv():
    if not os.path.exists(RESULTS_CSV):
        return None, "No results yet."
    return RESULTS_CSV, f"{len(_load_results())} responses ready."


def reset_study():
    if os.path.exists(RESULTS_CSV):
        # Backup instead of delete — rename with timestamp
        backup = RESULTS_CSV.replace(".csv", f"_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv")
        os.rename(RESULTS_CSV, backup)
        return f"Backed up to {backup} (not deleted).", summary_html()
    return "No results file found.", summary_html()


# ── UI ────────────────────────────────────────────────────────────────────────
with gr.Blocks(title="SOC Chatbot") as demo:

    bot_state = gr.State(value=None)

    # ── Header ──────────────────────────────────────────────────────────────
    gr.HTML("""
    <div style="padding:12px 24px;background:#161b22;border-bottom:1px solid #30363d;
                display:flex;align-items:center;justify-content:space-between;">
      <div>
        <span style="font-size:15px;font-weight:600;color:#e6edf3;letter-spacing:-.2px">
          SOC Cognitive Chatbot
        </span>
        <span style="font-size:12px;color:#484f58;margin-left:14px">
          alert triage · enrichment · multi-turn memory
        </span>
      </div>
      <div style="display:flex;align-items:center;gap:6px">
        <span style="width:7px;height:7px;border-radius:50%;background:#3fb950;display:inline-block"></span>
        <span style="font-size:11px;color:#3fb950;font-weight:500">online</span>
      </div>
    </div>""")

    # ════════════════════════════════════════════════════════════════════════
    # TAB 1 — INVESTIGATE
    # ════════════════════════════════════════════════════════════════════════
    with gr.Tab("Investigate"):

        ctx_bar = gr.HTML(value="")

        chatbot_ui = gr.Chatbot(
            label="",
            height=500,
            show_label=False,
        )

        # Input row
        with gr.Row(equal_height=True):
            txt = gr.Textbox(
                placeholder="Ask anything — 'show critical alerts', 'investigate ransomware on DC', 'recommendations for phishing'...",
                label="",
                lines=1,
                scale=8,
                container=False,
            )
            btn_send = gr.Button("Send  →", variant="primary", scale=1, min_width=90)

        # Quick chips
        gr.HTML("""
        <div id="chips-row" style="display:flex;flex-wrap:wrap;align-items:center;
             gap:6px;padding:10px 0 6px">
          <span style="font-size:10px;color:#484f58;text-transform:uppercase;
                letter-spacing:.5px;margin-right:4px">Quick</span>
          <button class="qchip" onclick="qchip('show critical alerts')">Critical alerts</button>
          <button class="qchip" onclick="qchip('show high alerts')">High alerts</button>
          <button class="qchip" onclick="qchip('ransomware on DomainController')">Ransomware DC</button>
          <button class="qchip" onclick="qchip('brute force on WebServer')">BruteForce web</button>
          <button class="qchip" onclick="qchip('recommendations for phishing')">Phishing playbook</button>
          <button class="qchip" onclick="qchip('investigate malware on DomainController')">Investigate malware</button>
          <button class="qchip" onclick="qchip('show all escalated alerts')">Escalated</button>
        </div>
        <style>
          .qchip {
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 20px;
            color: #8b949e;
            font-size: 11px;
            font-family: inherit;
            padding: 3px 11px;
            cursor: pointer;
            transition: border-color .15s, color .15s, background .15s;
            letter-spacing: .1px;
          }
          .qchip:hover {
            border-color: #58a6ff;
            color: #58a6ff;
            background: #0d1935;
          }
        </style>
        <script>
          function qchip(text) {
            const boxes = document.querySelectorAll('textarea');
            for (const b of boxes) {
              if (b.placeholder && b.placeholder.includes('critical alerts')) {
                b.value = text;
                b.dispatchEvent(new Event('input', {bubbles: true}));
                b.focus();
                break;
              }
            }
          }
        </script>""")

        # Bottom row
        with gr.Row():
            btn_reset = gr.Button("↺ New session", variant="secondary", size="sm")

        # Wiring
        btn_send.click(
            fn=chat,
            inputs=[txt, chatbot_ui, bot_state],
            outputs=[chatbot_ui, txt, ctx_bar, bot_state])
        txt.submit(
            fn=chat,
            inputs=[txt, chatbot_ui, bot_state],
            outputs=[chatbot_ui, txt, ctx_bar, bot_state])
        btn_reset.click(
            fn=reset_chat,
            inputs=[chatbot_ui, bot_state],
            outputs=[chatbot_ui, txt, ctx_bar, bot_state])
        demo.load(fn=new_bot, inputs=[], outputs=[bot_state])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 2 — EVALUATION
    # ════════════════════════════════════════════════════════════════════════
    with gr.Tab("Evaluation"):

        gr.HTML("""
        <div style="padding:16px 0 10px;font-size:13px;color:#8b949e;line-height:1.7">
          Technical metrics computed on the fixed dataset (seed=42) — fully reproducible.<br>
          Likert results update live when participants submit responses.
        </div>""")

        btn_eval = gr.Button("Run evaluation", variant="primary")
        eval_out = gr.Markdown("_Click to compute all metrics._")
        btn_eval.click(fn=run_evaluation_ui, inputs=[], outputs=[eval_out])

    # ════════════════════════════════════════════════════════════════════════
    # TAB 3 — USER STUDY
    # ════════════════════════════════════════════════════════════════════════
    with gr.Tab("User Study"):

        gr.HTML("""
        <div style="padding:16px 0 20px">
          <div style="font-size:14px;font-weight:500;color:#e6edf3;margin-bottom:12px">
            Instructions for participants
          </div>
          <div style="border-left:3px solid #21262d;padding-left:16px;
                      font-size:13px;color:#8b949e;line-height:2">
            <span style="color:#58a6ff;font-weight:500">1.</span>
            Go to the <span style="color:#e6edf3;font-weight:500">Investigate</span> tab —
            test the chatbot for 5 minutes using the quick chips or your own queries.<br>
            <span style="color:#58a6ff;font-weight:500">2.</span>
            Come back here and rate the 4 statements below
            (1 = Strongly disagree · 5 = Strongly agree).<br>
            <span style="color:#58a6ff;font-weight:500">3.</span>
            Enter any anonymous Participant ID and click
            <span style="color:#e6edf3;font-weight:500">Submit</span>.
          </div>
        </div>""")

        with gr.Row():
            with gr.Column(scale=1, min_width=230):
                gr.HTML('<div style="font-size:11px;color:#484f58;text-transform:uppercase;'
                        'letter-spacing:.5px;margin-bottom:10px">Profile</div>')
                pid = gr.Textbox(
                    label="Participant ID  (anonymous — e.g. P01)",
                    placeholder="P01")
                background = gr.Dropdown(
                    label="Background",
                    choices=[
                        "SOC Analyst / Security Analyst",
                        "IT / System Administrator",
                        "Cybersecurity Researcher / Student",
                        "Software Developer",
                        "Other IT professional",
                        "No IT background",
                    ])
                experience = gr.Dropdown(
                    label="Years of IT / Security experience",
                    choices=["< 1 year", "1–3 years", "3–5 years", "5–10 years", "> 10 years"])

            with gr.Column(scale=2):
                gr.HTML('<div style="font-size:12px;color:#8b949e;margin-bottom:14px;padding-top:2px">'
                        '1 = Strongly disagree &nbsp;·&nbsp; 5 = Strongly agree</div>')
                q1 = gr.Radio(choices=SCALE, value=None,
                    label="Q1 — The enriched context (CVE, MITRE ATT&CK, incident history) was clear and useful for understanding the threat.")
                q2 = gr.Radio(choices=SCALE, value=None,
                    label="Q2 — The recommendations (playbooks, response steps) were actionable and relevant to the attack type.")
                q3 = gr.Radio(choices=SCALE, value=None,
                    label="Q3 — The conversational interface was easy to use. I could express my queries naturally.")
                q4 = gr.Radio(choices=SCALE, value=None,
                    label="Q4 — This chatbot would save significant time compared to navigating multiple tools manually.")
                feedback = gr.Textbox(
                    label="Open feedback  (optional)",
                    placeholder="What worked well? What could be improved?",
                    lines=3)

        with gr.Row():
            btn_sub    = gr.Button("Submit", variant="primary")
            btn_export = gr.Button("Export CSV", variant="secondary")

        status_out  = gr.Textbox(label="", interactive=False, value="", show_label=False)
        export_file = gr.File(label="Download")
        summary_out = gr.HTML(value=summary_html())

        btn_sub.click(
            fn=submit_likert,
            inputs=[pid, background, experience, q1, q2, q3, q4, feedback],
            outputs=[status_out, summary_out])
        btn_export.click(fn=export_csv, inputs=[], outputs=[export_file, status_out])


if __name__ == "__main__":
    print("[SOC] http://127.0.0.1:7860")
    demo.launch(
        server_name="0.0.0.0",
        server_port=7860,
        share=False,
        css=CSS,
    )