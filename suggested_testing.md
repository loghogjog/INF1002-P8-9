# Email Phishing Detection Design Notes

## 🎯 Goal
Build a web application that accepts `.eml` files, extracts content & attachments, and determines whether the email is **Safe**, **Suspicious**, or **Malicious**.

---

## 🔍 Current Approach (Baseline Idea)
- Each detection module sets a **flag** (`safe`, `suspicious`, `malicious`).
- Collect all flags and decide verdict based on thresholds (e.g., 2+ malicious flags = malicious).

---

## ✅ Strengths
- **Modular** → Easy to add/remove detection methods.
- **Transparent** → Can explain why something was flagged.
- **Simple** → Quick to implement.

---

## ⚠️ Flaws & Pitfalls
1. **Unequal severity**  
   Not all detections should carry equal weight.  
   - Example: *“Attachment is an EXE with obfuscation”* is far more serious than *“Sender display name mismatch.”*

2. **False positives**  
   Too many low-confidence signals may incorrectly classify benign emails as malicious.

3. **False negatives**  
   If thresholds are too high, a phishing attempt with a **single strong indicator** may slip through.

4. **Rigid thresholds**  
   Static rules don’t adapt well to evolving phishing tactics.

---

## 💡 Suggested Improvements

### 1. Weighted Risk Scoring
Assign **weights** to each detection:

| Detection Method                     | Example Weight |
|--------------------------------------|----------------|
| Antivirus detects malware in attachment | +100 (Critical) |
| SPF/DKIM fail + display name spoof    | +70 (High)     |
| Suspicious link domain                | +40 (Medium)   |
| Generic heuristics (typos, urgency)   | +10 (Low)      |

**Scoring thresholds:**
- `>= 100` → **Malicious**
- `>= 50` → **Suspicious**
- `< 50` → **Safe**

---

### 2. Hard Override Rules
Certain red flags should immediately override everything else:
- Antivirus detects malware → always **Malicious**
- Executable attachment (`.exe`, `.js`, `.scr`) or double-extension (`invoice.pdf.exe`) → always **Malicious**

---

### 3. Suspicious vs Malicious
- **Suspicious** → needs human review (medium confidence).
- **Malicious** → confidently harmful (high confidence or confirmed malware).

---

### 4. Audit Trail
Always record which rules triggered the decision:

```json
{
  "verdict": "Suspicious",
  "score": 70,
  "signals": [
    {"rule": "SPF fail", "severity": "High", "weight": 40},
    {"rule": "Suspicious link domain", "severity": "Medium", "weight": 30}
  ]
}
