# imports
from flask import Flask, request, render_template
from email import message_from_binary_file, policy
from email.utils import parseaddr
from modules.attachment_scanner import attachment_evaluation, get_file_extension, extract_attachments
from modules.whitelistandeditDistanceCheck import classify_sender
from modules import suspicious_url

# app configs
app = Flask(__name__)
app.config[
    'MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000  # 16MB - anitvirus API accepts a maxmimum of 10MB for attachments so an additional 6MB for the rest of the email should be plenty
app.config['UPLOAD_EXTENSIONS'] = ['eml']  # allow only eml files

# global variables
FILENAME = ""
SCAN_NO_RESULT_WEIGHT = 20
SAFE_RETURN_CODE = 0
SUSPICIOUS_RETURN_CODE = 1
MALICIOUS_RETURN_CODE = 2
INVALID_RETURN_CODE = -1


@app.route('/', methods=['GET'])
def index():
    return render_template('index.html', response=None)


@app.route('/', methods=['POST'])
def upload():
    '''
    This is the main function where uploaded .eml
    files are sent to for processing and analysing
    '''

    # result baseline
    overall_scan_result = {
        "verdict": "unknown",
        "score": 0,
        "signals": []
    }

    file = request.files.get("email_file")
    file_extension = get_file_extension(file.filename)

    # check if file exists and file type is accepted and no double extensions
    if not file or file_extension not in app.config['UPLOAD_EXTENSIONS'] or len(file_extension.split('.')) > 2:
        return render_template("index.html", response_code=INVALID_RETURN_CODE,
                               reasons=["Missing File"] if not file else ["Only .eml files are accepted"])

    # file passed validity checks
    file.stream.seek(0)
    msg = message_from_binary_file(file.stream, policy=policy.default)

    # tristan's parts:
    ''' get sender's address '''
    raw_from = msg["From"]
    _, sender_email = parseaddr(raw_from)
    ''' whitelist check + edit distance check, then add into results '''
    overall_scan_result['signals'].append(classify_sender(sender_email))

    ''' Attachment Scanning '''
    attachments = extract_attachments(msg)
    # try:
    if attachments:  # attachments found
        attachments_results = attachment_evaluation(attachments)
        if attachments_results:
            for attachment in attachments_results:
                attachment_scan_final_result, attachment_severity, attachment_final_weight, attachment_scan_reasons = attachment
                overall_scan_result['signals'].append({
                    "rule": attachment_scan_final_result,
                    "severity": attachment_severity,
                    "weight": attachment_final_weight,
                    "reasons": attachment_scan_reasons
                })
        else:  # no scan result
            overall_scan_result['signals'].append({
                "rule": "Attachment Scan Unknown Results",
                "severity": "Suspicious",
                "weight": SCAN_NO_RESULT_WEIGHT,
            })
    else:
        overall_scan_result['signals'].append({
            "rule": "No Attachments Found",
            "severity": "Info",
            "weight": 0,
        })

    '''Suspicious url scanning'''
    with open("modules/suspicious_url.py", "rb") as f:
        text = suspicious_url.extract_eml_txt(f)

        urls = suspicious_url.extract_urls(text)
        results = []

        for url in urls:
            vt_result = suspicious_url.push_to_virustotal(url)
            evaluation = suspicious_url.evaluate_url_risk(url, vt_result)
            results.append(evaluation)

        return render_template("results.html", results=results, file=file.filename)

    return render_template("index.html")

    # except Exception as e:
    #   print(f"Error occured during attachment scan: {e}")

    # Overall Evalutation of Risk Score
    total_risk_score = sum([risk['weight'] for risk in overall_scan_result['signals']])
    moderated_risk_score = min(100, total_risk_score)
    if moderated_risk_score < 50:
        verdict = SAFE_RETURN_CODE
    elif moderated_risk_score < 100:
        verdict = SUSPICIOUS_RETURN_CODE
    else:
        verdict = MALICIOUS_RETURN_CODE
    overall_scan_result['verdict'] = verdict
    overall_scan_result['score'] = moderated_risk_score
    print(overall_scan_result)

    return render_template("index.html", response=overall_scan_result)


if __name__ == '__main__':
    app.run(debug=True)
