## Project PhishGuard - INF1002-P8-9
```
This is a simple web page that runs rule-based phishing email analysis.
It performs a series of checks on a .eml file.
1. Keyword Detection
2. Keyword Positioning Scoring
3. Whitelist Check
4. Edit Distance Check
5. Suspicious URL Detection
6. Attachment Scan
```

## Installation
```bash
git clone https://github.com/loghogjog/INF1002-P8-9.git
```

## SETUP
```bash
# Install your own Tailwind CLI into the project folder as this project does not use Node.js, 
Install tailwind CSS standalone CLI from https://github.com/tailwindlabs/tailwindcss/releases/tag/v4.1.13 and rename to tailwindcss

# build your own output.css as tailwind compiles differently for different OS
./tailwindcss -i static/src/input.css -o static/dist/output.css 

# install the required libraries
pip install -r requirements.txt

# get your API keys at the following links
AttachmentAV: https://attachmentav.com/subscribe/api/
VirusTotal: https://www.virustotal.com/gui/my-apikey

# create and paste the following into your .env file
ATTACHMENT_API_KEY=<attachmentAV_api_key>
ANTIVIRUS_URL=https://eu.developer.attachmentav.com/v1/scan/sync/binary
URL_SCAN_API_KEY=<virustotal_api_key>

python app.py

# only .eml files accepted
```
 
