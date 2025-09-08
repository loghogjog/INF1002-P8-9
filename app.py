from flask import Flask, request
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB (TBC)

ALLOWED_EXTENSIONS = {".eml"}

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/upload', methods=['POST'])
def upload_eml_file():
    if 'file' not in request.files:
        return "No file part", 400
    


if __name__== '__main__':
    app.run(debug=True)