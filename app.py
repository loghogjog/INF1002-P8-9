# imports
from flask import Flask, request, render_template
#from werkzeug.utils import secure_filename
import os
from email import message_from_binary_file
from modules.scanner import extract_attachments, is_attachment_safe, get_file_extension, ANTIVIRUS_SCAN_WEIGHT

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

    ''' Attachment Scanning '''
    attachments = extract_attachments(msg) # list of attachment extension & binary data
    print(attachments)
    if attachments: # attachments extracted
        # perform analysis
        attachments_scan_results = map(is_attachment_safe, attachments) # list of list of results
        try:
            for status in list(attachments_scan_results): # list of scan results
                if status:    
                    total_weight = sum([check['weight'] for check in status])
                    final_weight = min(total_weight, 100) # sets weight limit to 100

                    if final_weight == 100: # override: instantly flagged as malicious 
                        attachment_scan_final_result = "Fail"
                        attachment_severity = "Critical"
                    elif final_weight >= 50:
                        attachment_scan_final_result = "Potentially Unsafe"
                        attachment_severity = "Suspicious"
                    else:
                        attachment_scan_final_result = "Safe"
                        attachment_severity = "Safe"
                    overall_scan_result['signals'].append({
                            "rule" : "Attachment Scan " + attachment_scan_final_result,
                            "severity" : attachment_severity,
                            "weight" : final_weight # 100
                        })
                else:
                    print("No scan results")
        except KeyError as e:
                print(f"KeyError: {e}")
        finally:
            print(overall_scan_result)
    else:
        print("No Attachments Extracted")
        overall_scan_result['signals'].append({
             "rule":"No Attachments Found",
             "severity":"Info",
             "weight": 0
        })

    #store logs?

    # process the file and update list_of_reasons
    # call custom functions here
    # finally, evaluate risk score of email and decide on the return code
    #code = SAFE_RETURN_CODE / SUSPICIOUS_RETURN_CODE / MALICIOUS_RETURN_CODE
    return render_template("index.html", response_code=SAFE_RETURN_CODE, reasons=overall_scan_result['signals'])

    
    
    


if __name__== '__main__':
    app.run(debug=True)