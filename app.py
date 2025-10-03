# imports
from flask import Flask, request, render_template
from email import message_from_binary_file, policy
from email.utils import parseaddr
from modules.attachment_scanner import attachment_evaluation, get_file_extension, ANTIVIRUS_SCAN_WEIGHT, extract_attachments

# app configs
app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 16 * 1000 * 1000 # 16MB - anitvirus API accepts a maxmimum of 10MB for attachments so an additional 6MB for the rest of the email should be plenty
app.config['UPLOAD_EXTENSIONS'] = ['eml'] # allow only eml files

# global variables
FILENAME = ""
SAFE_RETURN_CODE = 0
SUSPICIOUS_RETURN_CODE = 1
MALICIOUS_RETURN_CODE = 2
INVALID_RETURN_CODE = -1
# result baseline
overall_scan_result = { 
    "verdict": "unknown",
    "score": 0,
    "signals": []
}

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def upload():
    '''
    This is the main function where uploaded .eml 
    files are sent to for processing and analysing
    '''
    file = request.files.get("email_file")
    file_extension, ext_count = get_file_extension(file.filename)
    print(file_extension)

    # check if file exists and file type is accepted and no double extensions
    if not file or file_extension not in app.config['UPLOAD_EXTENSIONS'] or ext_count > 2:
        return render_template("index.html", response_code=INVALID_RETURN_CODE, reasons=["Missing File"] if not file else ["Only .eml files are accepted"])

    # file passed validity checks
    file.stream.seek(0)
    msg = message_from_binary_file(file.stream)
    
    #tristan's parts:
    ''' get sender's address '''
    raw_from = msg["From"]
    name, sender_email = parseaddr(raw_from)
    ''' whitelist check + edit distance check, then add into results '''
    overall_scan_result['signals'].append(classify_sender(sender_email))

    
    ''' Attachment Scanning '''
    attachments = extract_attachments(msg)
    print(attachments)
    if attachments: # attachments found
        attachment_scan_final_result, attachment_severity, attachment_final_weight = attachment_evaluation(attachments)
    else:
        attachment_scan_final_result = "No Attachments Found"
        attachment_severity = "Info"
        attachment_final_weight = 0

    overall_scan_result['signals'].append({
            "rule" : attachment_scan_final_result,
            "severity" : attachment_severity,
            "weight" : attachment_final_weight
        })
    print(overall_scan_result)
    
    #store logs?

    # process the file and update list_of_reasons
    # call custom functions here
    # finally, evaluate risk score of email and decide on the return code
    #code = SAFE_RETURN_CODE / SUSPICIOUS_RETURN_CODE / MALICIOUS_RETURN_CODE
    return render_template("index.html", response_code=SUSPICIOUS_RETURN_CODE, reasons=overall_scan_result['signals'])

    
    
    


if __name__== '__main__':
    app.run(debug=True)
