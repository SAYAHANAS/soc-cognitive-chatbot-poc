# SOC Cognitive Chatbot - Proof of Concept

Code and data for the paper "A Cognitive Chatbot for SOC Augmentation:
Conceptual Model and Proof of Concept".

The PoC implements the Interface and Cognitive layers of the proposed
architecture: an intent-aware conversational pipeline (LLM classification
with a keyword fallback) on top of an interpretable risk score RS' with a
criticality-anchored safety floor.

## Files

- `soc_chatbot.py`: the PoC and the evaluation suite. Python stdlib only,
  except scikit-learn for the ML baselines.
- `soc_interface.py`: Streamlit web interface.
- `real_data_eval.py`: evaluation on the official UNSW-NB15 and
  CICIDS-2017 records.
- `intent_eval.py`: intent classifier accuracy on a 60-query labeled set.
- `make_roc_figure.py`: ROC figure (RS' vs CVSS+AV).
- `alerts.csv`: primary evaluation dataset (N=100).
- `unsw_alerts.csv`: UNSW-NB15-derived cross-validation set (N=500).
- `cicids_alerts.csv`: CICIDS-2017-derived cross-validation set (N=500).
- `user_study_results.csv`: anonymized pilot study responses.

The three alert CSVs are the canonical evaluation files. Every number in
the paper is computed from them. The `generate` command only creates a
CSV when it is absent and never overwrites an existing one.

## Reproducing the paper

```bash
pip install -r requirements.txt

python3 soc_chatbot.py evaluate          # main metrics + cross-dataset table
python3 soc_chatbot.py stats             # ablation, McNemar, window sensitivity
python3 soc_chatbot.py baselines-ml      # logistic regression / random forest
python3 soc_chatbot.py ci                # bootstrap 95% confidence intervals
python3 soc_chatbot.py optimize-weights  # constrained weight calibration
python3 intent_eval.py                   # intent classification accuracy
python3 make_roc_figure.py               # ROC figure
```

All randomness is seeded (seed = 42), so outputs are deterministic.

## Official benchmark records

`real_data_eval.py` runs the same pipeline on the published benchmark
files, scored against the datasets' own malicious/benign labels. The data
is not redistributed here; download it from the original sources:

- UNSW-NB15: UNSW_NB15_training-set.csv from
  https://research.unsw.edu.au/projects/unsw-nb15-dataset
- CICIDS-2017: the MachineLearningCVE CSVs from
  https://www.unb.ca/cic/datasets/ids-2017.html

```bash
python3 real_data_eval.py unsw   UNSW_NB15_training-set.csv 0 42
python3 real_data_eval.py cicids Wednesday-workingHours.pcap_ISCX.csv 0 42
```

## Running the chatbot

```bash
export GROQ_API_KEY=...     # optional, keyword fallback used otherwise
python3 soc_chatbot.py chat
```

or the web interface:

```bash
streamlit run soc_interface.py
```

## License

MIT, see LICENSE.
