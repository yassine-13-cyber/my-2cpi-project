import os   # This let Python interact with the operating system (like creating folders..)
import secrets  # Generate secure random tokens (download links)
from flask import Flask, send_file, abort, render_template_string  # Added render_template_string for custom error page
from werkzeug.utils import secure_filename  # Make sure filenames are safe

app = Flask(__name__)  # Create a web server object

FILE_TO_SERVE = "NOVAphones.rar"  # The file to host in the server
SECRET_DIR = "tokens"  # Folder to store tokens (links)
PORT = 5000  # Network port
SERVER_IP = "127.0.0.1"  # localhost only for presentation 

def validate_path(path):
    root_dir = os.path.abspath(os.path.dirname(__file__))  # Gets the full path
    target_path = os.path.abspath(os.path.join(root_dir, path))  # The folder that contains our file server.py
    if not target_path.startswith(root_dir):  # Ensure that no one can access files outside the project folder
        raise ValueError("Invalid path")
    return target_path

def setup_environment():
    os.makedirs(SECRET_DIR, exist_ok=True)  # Create example file if it doesn't exist
    if not os.path.exists(FILE_TO_SERVE):  # Prevent crashes
        with open(FILE_TO_SERVE, 'w') as f: 
            f.write("This is a test file for the one-time download server.")

@app.route('/download/<token>')  # When someone access the Token this function get to work
def download_file(token): 
    try:
        token = secure_filename(token)
        token_path = validate_path(os.path.join(SECRET_DIR, token))
        
        if not os.path.exists(token_path):
            abort(404, " You can't just redownload the ransomware!, no reversing for you.")
        
        os.remove(token_path)  # Deleting the token so the link will work once 
        return send_file(
            FILE_TO_SERVE,
            as_attachment=True,
            download_name=os.path.basename(FILE_TO_SERVE),
            conditional=True
        )
    except Exception as e:
        abort(500, f"Server error: {str(e)}")

@app.errorhandler(500)
def internal_server_error(e):
    return render_template_string("""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>Server Error</title>
        <style>
            body {
                background-color: #2e2e2e;
                color: #f44336;
                font-family: Arial, sans-serif;
                text-align: center;
                padding-top: 100px;
            }
            .error-container {
                background: #1e1e1e;
                border: 2px solid #f44336;
                display: inline-block;
                padding: 30px;
                border-radius: 10px;
            }
            h1 {
                font-size: 3em;
            }
            p {
                font-size: 1.2em;
                margin-top: 10px;
            }
        </style>
    </head>
    <body>
        <div class="error-container">
            <h1>Server Error</h1>
            <p>{{ error }}</p>
        </div>
    </body>
    </html>
    """, error=str(e)), 500

def generate_download_link():
    token = secrets.token_urlsafe(32)   # Create a random and more secure token
    token_path = validate_path(os.path.join(SECRET_DIR, token)) 
    
    with open(token_path, 'w') as f:
        f.write('')   # Create empty token file
    
    return f"http://{SERVER_IP}:{PORT}/download/{token}"

if __name__ == '__main__':  # Get to work when running the code
    setup_environment()  # Running the function that prepares folders/files
    
    test_link = generate_download_link()  # Creating the first accessible link 
    print(f"Server ready at http://{SERVER_IP}:{PORT}") 
    print(f"Test download link: {test_link}")  # Printing the download link in the console
    
    app.run(host=SERVER_IP, port=PORT, debug=False)  # Running the server
