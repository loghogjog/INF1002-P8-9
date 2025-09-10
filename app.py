from flask import Flask, request, render_template, redirect, url_for, flash
from werkzeug.utils import secure_filename

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads/'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Limit upload size to 16MB (TBC)

ALLOWED_EXTENSIONS = {".eml"}
FILENAME = ""
list_of_reasons = []

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/', methods=['GET'])
def home():
    return render_template('index.html', reasons=list_of_reasons)

@app.route('/upload', methods=['POST'])
def upload_eml_file():
    if 'file' not in request.files:
        flash('No file part')
        return redirect(request.url)
    file = request.files['file']
    if file.filename == '':
        flash('No selected file')
        return redirect(request.url)
    if file and allowed_file(file.filename):
        # insert filename hashing here
        filename = secure_filename(file.filename)
        file.save(app.config['UPLOAD_FOLDER'] + filename)
        global FILENAME
        FILENAME = filename
        # process the file and update list_of_reasons
        # call custom functions here
        return redirect(url_for('home'))

    
    
    


if __name__== '__main__':
    app.run(debug=True)