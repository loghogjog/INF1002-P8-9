import re

def levenshtein_distance(word1, word2):
    """Dynamic programming solution"""
    m = len(word1)
    n = len(word2)
    table = [[0] * (n + 1) for _ in range(m + 1)]

    for i in range(m + 1):
        table[i][0] = i
    for j in range(n + 1):
        table[0][j] = j

    for i in range(1, m + 1):
        for j in range(1, n + 1):
            if word1[i - 1] == word2[j - 1]:
                table[i][j] = table[i - 1][j - 1]
            else:
                table[i][j] = 1 + min(table[i - 1][j], table[i][j - 1], table[i - 1][j - 1])
                
    return table[-1][-1]


def load_whitelist(filename="whitelist.txt"):
    with open(filename, "r") as f:
        return [line.strip().lower() for line in f if line.strip()]


WHITELIST = load_whitelist()


def extract_domain(email_address):
    match = re.search(r'@([A-Za-z0-9.-]+)', email_address)
    return match.group(1).lower() if match else None


def is_whitelisted(domain):
    return domain in WHITELIST


def is_suspicious(domain, threshold=2):
    for trusted_domain in WHITELIST:
        if levenshtein_distance(domain, trusted_domain) <= threshold:
            return True, trusted_domain
    return False, None


def classify_sender(email_address):
    domain = extract_domain(email_address)
    if not domain:
        return "Invalid email"

    if is_whitelisted(domain):
        return {"rule" : "Trusted sender (in whitelist)",
                "severity" : "Info",
                "weight" : 0}

    suspicious, target_domain = is_suspicious(domain)
    if suspicious:
        rule = f"Scam Likely (similar to {target_domain})"
        severity = "Critical"
        weight = 42

    else:
        rule = "Unverified/Suspicious (sender is not whitelisted nor within threshold limit of trying to impersonate)"
        severity = "Suspicious"
        weight = 67

    return {"rule" : rule,
            "severity" : severity,
            "weight" : weight}


if __name__ == "__main__":
    print("How to use: overall_scan_result['signals'].append(classify_sender(sender_email))")
    

