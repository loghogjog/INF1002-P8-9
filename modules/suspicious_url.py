def extract_urls(text):

    urls = []
    words = text.split()
    for word in words:
        if word.startswith("http://") or word.startswith("https://"):
            remove_beyond_puncutation = word.strip(".,;?!")
            urls.append(remove_beyond_puncutation)
        return urls

def is_ip_addr(domain):
    parts = domain.split(".")
    if len(parts) != 4:
        return False
    for part in parts:
        if not part.isdigit():
            return False
        if not (0 < int(part) <= 255):
            return False
    return True

def detect_susp_urls(email, claimed_domain=None):
    suspicious = []
    urls = extract_urls(email)

    for url in urls:
        domain = url.split("//", 1)[-1]
        if "/" in domain:
            domain = domain.split("/", 1)[0]

        if is_ip_addr(domain):
            suspicious.append(url, "IP Address detected!")
            continue

        if claimed_domain and claimed_domain not in domain:
            suspicious.append(url, "Domain mismatched!")
            continue

    return suspicious

def suspicious_url_detector(email_text):
    
    
    
    
    
    
    
    
    try:
        with open(email_text, 'rb') as file:
            file_content = file.read()
            print(file_content)

    except FileNotFoundError:
        print(f"Error, file not found!")

    claimed_safe_domain = "????"
    results = detect_suspicious_urls(email_text, claimed_safe_domain)


