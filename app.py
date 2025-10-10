# imports
from flask import Flask, jsonify, request, render_template
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
    This is the main function where uploaded .eml files are sent to for processing and analysing
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
        return render_template("index.html", response_code=INVALID_RETURN_CODE, reasons=["Missing File"] if not file else ["Only .eml files are accepted"])

    # file passed validity checks
    file.stream.seek(0)
    msg = message_from_binary_file(file.stream, policy=policy.default)
    
    ''' get sender's address '''
    raw_from = msg["From"]
    _, sender_email = parseaddr(raw_from)
    ''' whitelist check + edit distance check, then add into results '''
    overall_scan_result['signals'].append(classify_sender(sender_email))

    
    ''' Attachment Scanning '''
    attachments = extract_attachments(msg)
    try:
        if attachments: # attachments found
            attachments_results = attachment_evaluation(attachments)
            if attachments_results:
                for attachment in attachments_results:
                    attachment_scan_final_result, attachment_severity, attachment_final_weight, attachment_scan_reasons = attachment
                    overall_scan_result['signals'].append({
                        "rule" : attachment_scan_final_result,
                        "severity" : attachment_severity,
                        "weight" : attachment_final_weight,
                        "reasons": attachment_scan_reasons
                    })
            else: # no scan result
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

    except Exception as e:
        print(f"Error occured during attachment scan: {e}")
        overall_scan_result['signals'].append({
            "rule": "Attachment Scan Unknown Results",
            "severity": "Suspicious",
            "weight": SCAN_NO_RESULT_WEIGHT,
        })

    try:

        file.stream.seek(0)
        email_text = suspicious_url.extract_eml_txt(file.stream)

        urls = suspicious_url.extract_urls(email_text)

        if urls:
            for url in urls:
                vt_result = suspicious_url.push_to_virustotal(url)
                url_eval = suspicious_url.evaluate_url_risk(url, vt_result)

       
                #reasons_text = [
                #    f"{desc} (Severity: {sev}, +{w}pts)"
                #    for desc, sev, w in url_eval["details"]
                #]

                print(url_eval['url'])
                signal_entry = {
                    "rule": "URL Analysis",
                    "severity": url_eval["final_risk"],
                    "weight": url_eval["total_weight"],
                    "reasons": "Suspicious URL: " + url_eval["url"],
                }


                if url_eval.get("virustotal_link"):
                    signal_entry["virustotal_link"] = url_eval["virustotal_link"]

                overall_scan_result["signals"].append(signal_entry)

        else:
            overall_scan_result["signals"].append({
                "rule": "No URLs Found",
                "severity": "Info",
                "weight": 0,
                "reasons": []
            })

    except Exception as e:
        print(f"Error occurred during URL scan: {e}")
        overall_scan_result["signals"].append({
            "rule": "URL Scan Failed",
            "severity": "Suspicious",
            "weight": 20,
            "reasons": [str(e)]
        })

    # Overall Evalutation of Risk Score
    total_risk_score = sum([risk['weight'] for risk in overall_scan_result['signals']])
    moderated_risk_score = min(100, total_risk_score)
    if moderated_risk_score < 40:
        verdict = SAFE_RETURN_CODE
    elif moderated_risk_score < 100:
        verdict = SUSPICIOUS_RETURN_CODE
    else:
        verdict = MALICIOUS_RETURN_CODE
    overall_scan_result['verdict'] = verdict
    overall_scan_result['score'] = moderated_risk_score
    print(overall_scan_result)
    
    # For automated testing
    if request.headers.get("Accept") == "application/json":
        return jsonify(overall_scan_result)
    # Actual HTML return
    return render_template("index.html", response=overall_scan_result)


if __name__== '__main__':
    app.run(debug=True)
