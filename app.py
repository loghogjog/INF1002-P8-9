from flask import Flask, request, render_template
from werkzeug.utils import secure_filename

app = Flask(__name__)

ALLOWED_EXTENSIONS = {".eml"}
FILENAME = ""
SAFE_RETURN_CODE = 0
SUSPICIOUS_RETURN_CODE = 1
MALICIOUS_RETURN_CODE = 2
INVALID_RETURN_CODE = -1
LIST_OF_REASONS = []

def allowed_file_extension_check(filename):
    '''
    This function compares the uploaded flie extension against ALLOWED_EXTENSIONS whitelist
    Good for scaling in the future should more extensions ever be allowed.
    '''
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/', methods=['POST'])
def upload():
    file = request.files.get("email_file")

    # Double check if file exists and file type is accepted
    if not file or not allowed_file_extension_check(file.filename):
        return render_template("index.html", response_code=INVALID_RETURN_CODE, reasons=["Missing File"] if not file else ["File uploaded must be EML file"])

    # File upload passed validity checks    
    global FILENAME
    FILENAME = secure_filename(file.filename)

    # process the file and update list_of_reasons
    # call custom functions here
    # finally, evaluate risk score of email and decide on the return code
    #code = SAFE_RETURN_CODE / SUSPICIOUS_RETURN_CODE / MALICIOUS_RETURN_CODE
    return render_template("index.html", response_code=SAFE_RETURN_CODE, reasons=LIST_OF_REASONS)

    
    
    


if __name__== '__main__':
    app.run(debug=True)