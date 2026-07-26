"""Intent-classifier accuracy on a labeled query set.

60 analyst queries (20 per intent: filter / investigate / recommend).
The keyword parser is deterministic, so results are machine-independent.

Usage:
  python3 intent_eval.py          # keyword fallback
  python3 intent_eval.py --llm    # also test the LLM path (needs GROQ_API_KEY)
"""

import sys
from soc_chatbot import _kw_parse

# (query, gold_intent)
QUERIES = [
    # filter
    ("show me all critical alerts",                          "filter"),
    ("list high severity alerts",                            "filter"),
    ("display malware alerts",                               "filter"),
    ("show phishing alerts on the mail server",              "filter"),
    ("any ransomware today",                                 "filter"),
    ("give me the escalated alerts",                         "filter"),
    ("show suppressed alerts",                               "filter"),
    ("list brute force attempts",                            "filter"),
    ("what alerts do we have on the database",               "filter"),
    ("show me everything on the domain controller",          "filter"),
    ("critical alerts on the web server",                    "filter"),
    ("list all data exfiltration events",                    "filter"),
    ("show alerts sorted by risk",                           "filter"),
    ("high and critical alerts please",                      "filter"),
    ("what happened on the file server",                     "filter"),
    ("show me the latest alerts",                            "filter"),
    ("any failed login alerts",                              "filter"),
    ("display alerts from the mail server",                  "filter"),
    ("list medium criticality alerts",                       "filter"),
    ("show all alerts",                                      "filter"),
    # investigate
    ("investigate alert 17",                                 "investigate"),
    ("tell me more about alert 42",                          "investigate"),
    ("details on alert 5",                                   "investigate"),
    ("analyze alert 88",                                     "investigate"),
    ("what is alert 23 about",                               "investigate"),
    ("deep dive into alert 61",                              "investigate"),
    ("explain alert 9",                                      "investigate"),
    ("investigate the malware on workstation-07",            "investigate"),
    ("look into alert 33",                                   "investigate"),
    ("examine alert 76",                                     "investigate"),
    ("give me the full context of alert 12",                 "investigate"),
    ("why was alert 54 escalated",                           "investigate"),
    ("show the cve for alert 29",                            "investigate"),
    ("what mitre technique is alert 3",                      "investigate"),
    ("inspect alert 45",                                     "investigate"),
    ("alert 67 details",                                     "investigate"),
    ("dig into alert 81",                                    "investigate"),
    ("investigate the ransomware on the file server",        "investigate"),
    ("history of alert 20",                                  "investigate"),
    ("check alert 91",                                       "investigate"),
    # recommend
    ("what should i do about alert 17",                      "recommend"),
    ("recommend actions for alert 42",                       "recommend"),
    ("how do i respond to this ransomware",                  "recommend"),
    ("give me remediation steps for alert 5",                "recommend"),
    ("what are the next steps for alert 23",                 "recommend"),
    ("how should we handle the phishing alert",              "recommend"),
    ("mitigation for alert 61",                              "recommend"),
    ("suggest a response for alert 9",                       "recommend"),
    ("what actions for the malware on the database",         "recommend"),
    ("recommend a course of action for alert 33",            "recommend"),
    ("how to contain alert 76",                              "recommend"),
    ("response plan for alert 12",                           "recommend"),
    ("what do you advise for alert 54",                      "recommend"),
    ("countermeasures for alert 29",                         "recommend"),
    ("how do we fix alert 3",                                "recommend"),
    ("best response to the brute force on the dc",           "recommend"),
    ("recommend remediation for alert 45",                   "recommend"),
    ("what should the analyst do about alert 67",            "recommend"),
    ("advise me on alert 81",                                "recommend"),
    ("playbook for alert 91",                                "recommend"),
]

INTENTS = ["filter", "investigate", "recommend"]


def evaluate(parse_fn, name):
    conf = {g: {p: 0 for p in INTENTS + ["other"]} for g in INTENTS}
    errors = []
    for q, gold in QUERIES:
        out = parse_fn(q)
        pred = out.get("intent") if isinstance(out, dict) else None
        pred = pred if pred in INTENTS else "other"
        conf[gold][pred] += 1
        if pred != gold:
            errors.append((q, gold, pred))
    correct = sum(conf[i][i] for i in INTENTS)
    n = len(QUERIES)
    print(f"\n{'='*64}\n  INTENT CLASSIFICATION  |  {name}  |  {n} labeled queries"
          f"\n{'='*64}")
    print(f"  Accuracy: {correct}/{n} = {correct/n*100:.1f}%\n")
    print(f"  {'gold \\\\ pred':14s}" + "".join(f"{p:>13s}" for p in INTENTS + ["other"]))
    for g in INTENTS:
        row = "".join(f"{conf[g][p]:13d}" for p in INTENTS + ["other"])
        pr = conf[g][g] / sum(conf[g].values())
        print(f"  {g:14s}{row}   recall={pr:.2f}")
    if errors:
        print("\n  Misclassified:")
        for q, g, p in errors:
            print(f"    [{g:11s} -> {p:11s}]  \"{q}\"")
    return correct / n


if __name__ == "__main__":
    evaluate(lambda q: _kw_parse(q, {}), "keyword fallback (deterministic)")
    if "--llm" in sys.argv:
        from soc_chatbot import call_llm_nlu
        evaluate(lambda q: call_llm_nlu(q, {}), "LLM path (Groq)")
