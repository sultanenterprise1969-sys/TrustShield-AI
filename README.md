# [TEAM NAME] — TrustShield AI

**Detect the Signs. Understand the Risk. Stay Protected.**
IBM Z Datathon 2026 · Event code: **SSF2026**

TrustShield AI helps ordinary people (students, families, small businesses) judge whether a link, email, SMS/WhatsApp
message or screenshot shows signs of phishing or a scam. It gives a transparent 0–100 score, the evidence behind it,
a plain-language explanation and safe next steps. It never claims to catch every scam or to prove anything is safe.

---
## 1. What is genuinely implemented (and how well it was verified)

| Feature | Status | Verified in the build environment? |
|---|---|---|
| Link scanner (parsing, 15+ indicators, no network access, no redirects followed) | Implemented | Yes – unit tests, incl. a test that fails if any socket is opened |
| Message scanner (9 indicator families + snippets, link extraction, sender/brand checks) | Implemented | Yes – unit tests |
| Image scanner (validation → Pillow → Tesseract OCR → message pipeline) | Implemented | Yes – incl. real OCR end-to-end test (Tesseract was installed) |
| Shared risk scoring (dedupe, 0–100, categories, limitations, "Insufficient evidence") | Implemented | Yes |
| scikit-learn URL model (train / save / load / fallback) | Implemented | Yes – trained and evaluated, see §5 |
| Explanation layer (template always; optional LLM with fallback and guardrails) | Implemented | Template + fallback paths: yes. **A live LLM call: not tested** (no internet) |
| Login threat analysis (rules + IsolationForest on synthetic CSV) | Implemented | Yes |
| SQLite scan history (summaries only, delete button) | Implemented | Yes |
| Streamlit dashboard (7 pages) | Implemented | Partly – every page was executed against a *stub* Streamlit (smoke test). **Not yet opened in a real browser** (Streamlit could not be installed offline). |
| FastAPI backend (6 endpoints) | Implemented | **Not run here** (FastAPI could not be installed offline). Code compiles and API tests are written; run `pytest tests/test_api.py` after installing. |
| External reputation check (Google Safe Browsing) | Optional, off by default | **Not tested against the live API** |
| Run on IBM LinuxONE | Documented, **not yet tested** | See the checklist in §7 – the team must fill this in honestly |

Not implemented: forged-logo / deepfake / edited-receipt detection, non-English text rules, live URL fetching (deliberately),
user accounts, a calibrated model.

## 2. Problem, users, solution
Phishing and payment scams reach students and small businesses daily, and most people have no quick way to check a
suspicious message. TrustShield AI is a paste-and-check tool that shows *why* something looks risky so users learn the signs.

## 3. Architecture (hybrid AI)
```
 link / message / screenshot / login CSV
            │
   scanners/*  ── rules ──► Indicators ┐
   ai/predictor (scikit-learn) ────────┤   PREDICTIVE AI  (Component A)
                                       ▼
                       services/risk_scoring  → score 0-100 + category + evidence + limitations
                                       │
                       ai/explainer  (template, or optional LLM)   GENERATIVE AI  (Component B)
                                       ▼
                     Streamlit UI (app.py) / FastAPI (api.py) / CLI (scan_cli.py)  → services/history (SQLite)
```
* **Predictive AI** produces the score. The ML model adds at most 20 points because its output is *uncalibrated*.
* **Generative AI** only explains. It receives labels/scores (message snippets only if explicitly allowed), cannot change the score,
  and its output is rejected if it over-claims ("definitely a scam"). Any failure falls back to the template.
* **Evaluated independently:** model → `python -m ai.model_training` (precision/recall/F1/confusion matrix);
  explainer → `python -m unittest tests.test_explainer`; scoring → `tests/test_risk_scoring.py`.

Folder map: `scanners/` (url, message, image, login) · `ai/` (features, model_training, predictor, explainer) ·
`services/` (risk_scoring, history, threat_intel) · `utils/validation.py` · `data/` · `models/` · `tests/` · `deploy/`.

## 4. Quick start (Linux, Python 3.10+)
```bash
sudo apt install -y tesseract-ocr          # or: sudo dnf install tesseract  /  sudo zypper install tesseract-ocr
cd trustshield
python3 -m venv venv && source venv/bin/activate
pip install --upgrade pip && pip install -r requirements.txt
cp .env.example .env                       # edit TEAM_NAME; leave optional integrations off
python data/generate_synthetic_data.py     # recreates the synthetic CSVs (already included)
python -m ai.model_training                # trains + evaluates + saves the model
python -m unittest discover -s tests -t .  # or: pytest
streamlit run app.py --server.address 127.0.0.1 --server.port 8501
# optional API:   uvicorn api:app --host 127.0.0.1 --port 8000     (docs at /docs)
# no UI needed:   python scan_cli.py url "http://paypal.secure-login.xyz/verify"
```
`bash deploy/setup.sh` runs all of the setup in one go.

## 5. Model and measured results
* Data: `data/urls_synthetic.csv` – **2,400 SYNTHETIC URLs** produced by templates in `data/generate_synthetic_data.py`
  (1,500 "benign-looking", 900 "suspicious-looking", seed 42, duplicates removed). Labels describe how rows were *built*, not verified threat intelligence.
* Model: StandardScaler + LogisticRegression (21 URL features). 80/20 stratified split, `random_state=42`; fitted on the training part only.
* Result on the held-out 480-row test set (from our build run on x86-64, Python 3.12, scikit-learn 1.8.0):
  precision **0.92**, recall **0.894**, F1 **0.907**; confusion matrix `[[286, 14], [19, 161]]` (rows = actual benign/suspicious).
* **These numbers say the pipeline works. They are not real-world accuracy** – the test data comes from the same generator as the training data.
  To evaluate honestly, train on a real public phishing-URL dataset: `python -m ai.model_training --data your.csv --real-data` (columns `url,label`).
* Retrain on the IBM Z instance and quote *those* numbers (`models/metrics.json`), not ours.
* Security note: model files are pickles – only load files you trained yourself.

## 6. API (FastAPI)
`POST /api/scan/url` · `POST /api/scan/message` · `POST /api/scan/image` (multipart) · `POST /api/scan/login` (CSV upload) ·
`GET /api/history` · `GET /api/health`. All replies: `{"ok": bool, "data": {...}|null, "error": "..."|null}`.
Inputs are size-limited, CORS is restricted to `CORS_ORIGINS`, and unexpected errors return a generic message (no stack traces).

## 7. IBM LinuxONE / IBM Z deployment
**What runs where.** Everything runs on the LinuxONE instance: the Streamlit UI, the scanners, model training and inference
(CPU scikit-learn – no GPU or special accelerator is used), OCR (Tesseract), and SQLite history. The generative explanation is the
built-in template by default, so the whole app works with no external service. If the team configures an LLM, only the explainer
calls it (HTTPS, only after the user ticks a consent box).

**Steps.** Follow §4 on the instance, then reach the dashboard (Community Cloud instances often expose only SSH):
```bash
ssh -L 8501:localhost:8501 <user>@<instance-address>     # run on your laptop, then open http://localhost:8501
```
Only open a public port if your environment provides one, and then put it behind authentication. For auto-start use
`deploy/trustshield.service` (systemd) – edit the user and paths first. Containers: not provided; use them only if your environment supports them.

**Troubleshooting (s390x is big-endian IBM Z; wheels may be missing)**
* `pip` compiles numpy/scipy/scikit-learn slowly or fails → `sudo apt install build-essential gfortran libopenblas-dev python3-dev` (or the dnf/zypper equivalents), or use distro packages (`python3-numpy`, `python3-pandas`, `python3-scikit-learn`) with `python3 -m venv --system-site-packages venv`.
* **`pyarrow` (a Streamlit dependency) fails on s390x** – a known risk. Options: install the distro/conda pyarrow package, or install `requirements-core.txt` and use the API + `/docs` page and `scan_cli.py` instead of Streamlit. The analysis code does not need Streamlit.
* `TesseractNotFoundError` → install the `tesseract-ocr` package; the app still works without it (image scans report "OCR unavailable").
* "different features / could not be loaded" model message → retrain on the instance: `python -m ai.model_training`.

**Possible benefits (not measured).** Keeping scanning, OCR and optional model inference on one controlled server means messages and screenshots
need not leave the organisation's environment, and a Linux-on-Z deployment can be centrally managed. We make **no claim** of IBM Z acceleration or
performance advantage; if you want one, measure it (e.g. time 100 scans on the instance vs. your laptop) and report the real numbers.

**Tested on the IBM Z instance – fill in honestly before submitting**
- [ ] `uname -m` output: ________ , Python version: ________
- [ ] `pip install -r requirements.txt` succeeded (or which fallback was used): ________
- [ ] `python -m ai.model_training` run on the instance; F1 = ________
- [ ] `python -m unittest discover -s tests -t .` result: ________
- [ ] Dashboard reachable via: ________ ; all 7 pages opened: ________
- [ ] Optional LLM / reputation service used? ________ (if yes, what data was sent)

## 8. Privacy and safety
Links are never visited and redirects are never followed. No `eval`/`exec` on user input. Uploads are checked for extension, MIME type, file signature
and size (5 MB), processed in memory, and never written to disk. History stores only scan type, time, score, category and a short label – never message text,
OCR text, images or full links – and can be deleted from the History page. Secrets come from environment variables only. Results are automated indicators,
not a fraud determination, and the app is not a substitute for your bank, the police or a security professional.

## 9. Limitations and future work
English-only keyword rules · synthetic training data · uncalibrated model · small built-in brand/domain lists (not a threat feed) · text-only image analysis ·
single-language UI. Next: train on a real labelled dataset and calibrate, add more languages (e.g. Malay), calibrated confidence, user feedback loop, rate limiting and authentication for public hosting.

## 10. Three-minute demo script
1. *Problem* (20 s): one scam message people actually get.
2. *Link* (35 s): `http://paypal.secure-login.xyz/verify?next=http://evil.test/x` → score, evidence table, "local analysis only".
3. *Message* (35 s): `URGENT: Your PayPal account has been suspended. Verify your password and OTP within 24 hours at http://paypal-secure-login.xyz/verify` with sender `alerts@paypa1-support.com`.
4. *Image* (30 s): upload a screenshot of a similar message → OCR text → same pipeline.
5. *Hybrid AI* (30 s): show the ML note + evidence (predictive) and the plain-language "What this means" (generative/template). Mention the LLM is optional.
6. *LinuxONE* (20 s): show the dashboard served from the instance (`uname -m`).
7. *Repo* (10 s): GitHub link.

## 11. Datathon submission text (paste and edit)
> **[TEAM NAME] — TrustShield AI** (SSF2026). An open-source, hybrid predictive + generative AI tool that analyses links, messages and screenshots for scam indicators,
> scores them transparently, and explains the evidence and safe next steps in plain language. Built with Python, scikit-learn, Streamlit, FastAPI and Tesseract, deployed on IBM LinuxONE. 
> Results are automated assessments, not definitive fraud determinations.

Reminder: the brief asks for original code written and tested during the event. This codebase was generated with an AI assistant – read and understand it, test it yourselves, and follow the event's rules on disclosing AI assistance.
