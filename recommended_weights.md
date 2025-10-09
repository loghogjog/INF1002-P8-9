# 📊 Recommended Weights for Email Phishing Detection

These weights are intended for a **risk-scoring system**.  
- High-confidence red flags = **Critical** (100 points, instant malicious if override rule applies).  
- Medium confidence signals = **50–70 points**.  
- Weak heuristics = **10–30 points**.  

---

## 1. Attachment Analysis

| Detection | Severity | Weight |
|-----------|----------|--------|
| Antivirus scan reports malware | Critical | +100 |
| Executable attachment (`.exe`, `.js`, `.scr`, `.vbs`, etc.) | Critical | +100 |
| Double-extension trick (`invoice.pdf.exe`) | Critical | +100 |
| MIME type mismatch (declared `application/pdf` but is actually EXE) | High | +80 |
| Suspicious compressed file (`.zip`, `.rar`, password-protected) | High | +70 |
| Macro-enabled Office doc (`.docm`, `.xlsm`) | High | +70 |
| Uncommon file type (e.g. `.iso`, `.img`) | Medium | +50 |
| Large unusual attachment (>5 MB, unless media) | Low | +20 |

---

## 2. Link/URL Analysis

| Detection | Severity | Weight |
|-----------|----------|--------|
| Link domain on known phishing blacklist | Critical | +100 |
| Mismatched link text vs actual URL (e.g. `paypal.com` → `evil.com`) | High | +70 |
| Newly registered domain (e.g., < 30 days old) | High | +60 |
| Internationalized domain trick (IDN homograph attack) | High | +60 |
| Obfuscated/encoded URL (`hxxp`, IP literal, long hex encoding) | Medium | +40 |
| URL shortener used (bit.ly, tinyurl) | Low | +20 |

---

## 3. Header & Authentication Analysis

| Detection | Severity | Weight |
|-----------|----------|--------|
| SPF fail **and** DKIM fail | High | +70 |
| DMARC fail | High | +70 |
| Display name spoofing (From: "Amazon" <random@domain>) | Medium | +50 |
| "Reply-To" domain mismatch with "From" domain | Medium | +50 |
| HELO/EHLO hostname mismatch | Medium | +40 |
| X-Mailer header spoofed/empty | Low | +20 |

---

## 4. Content/Body Analysis

| Detection | Severity | Weight |
|-----------|----------|--------|
| Known phishing keywords ("urgent action required", "account suspended") | Medium | +40 |
| Excessive HTML obfuscation (base64 inline HTML, hidden text) | Medium | +40 |
| Embedded scripts (JavaScript/VBScript in HTML) | High | +70 |
| Inline images that link externally (tracking pixels, hidden beacons) | Low | +20 |
| Language mismatch (sender domain country vs email language) | Low | +20 |

---

## 5. Heuristics & Context

| Detection | Severity | Weight |
|-----------|----------|--------|
| First-time sender (not in known safe list) | Low | +20 |
| Unusual sending time (e.g., midnight in sender’s timezone) | Low | +10 |
| High ratio of images-to-text (common in spam/phish) | Low | +15 |
| Suspicious attachment + suspicious URL together | Override | Escalate to **Malicious** |

---

## 🚨 Overrides
- **Any Critical detection** (antivirus hit, executable attachment, known phishing URL) → **Malicious** immediately.  
- **Combination rule**: Multiple Mediums (e.g., suspicious URL + macro doc) can escalate to Malicious.  

---

## 🔎 Suggested Thresholds
- **Safe**: < 50 points  
- **Suspicious**: 50–99 points  
- **Malicious**: ≥ 100 points OR override triggered  

---
