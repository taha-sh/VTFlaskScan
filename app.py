from flask import Flask, request, render_template, jsonify, redirect, url_for, session
import requests
import json
import time


app = Flask(__name__, template_folder='templates', static_folder='static')
app.secret_key = 'your_secret_key'  
class VirusTotalAPI:
    API_KEY = "your-api-key-here"
    BASE_URL = 'https://www.virustotal.com/vtapi/v2/file/'

    @classmethod
    def scan_file(cls, file):
        url = f"{cls.BASE_URL}scan"
        params = {'apikey': cls.API_KEY}
        files_dict = {'file': (file.filename, file.stream)}
        return requests.post(url, files=files_dict, params=params)

    @classmethod
    def get_report(cls, scan_id):
        url = f"{cls.BASE_URL}report"
        params = {'apikey': cls.API_KEY, 'resource': scan_id}
        return requests.get(url, params=params)

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/scan_file', methods=['POST'])
def scan_file():
    """
    This function scans a file uploaded by the user using VirusTotalAPI. 
    If the file is not uploaded, it returns an error message. 
    If the response from VirusTotalAPI contains an error, it returns an error message. 
    If the response contains a scan ID, it saves the filename and scan ID to the session for later retrieval.
    """
    file = request.files.get('file')
    if not file:
        return render_template('error.html', error="No file uploaded. Please select a file and try again.")

    response = VirusTotalAPI.scan_file(file)
    json_response, error = handle_response(response)

    if error:
        return render_template('error.html', error=error)

    scan_id = json_response.get('scan_id')
    if scan_id:
        # Save the filename and scan ID to the session for later retrieval
        session[scan_id] = file.filename
        return render_template('analysis.html', scan_id=scan_id)
    else:
        return render_template('error.html', error="Scan ID not found in the response.")

def handle_response(response):
    if response.status_code != 200:
        return None, f"Failed to scan the file. Received a {response.status_code} status code."

    try:
        return response.json(), None
    except json.JSONDecodeError:
        return None, "Received an invalid JSON response from the server."

@app.route('/check_status/<scan_id>')
def check_status(scan_id):
    response = VirusTotalAPI.get_report(scan_id)
    json_response, error = handle_response(response)

    if error:
        return jsonify({'status': 'error', 'message': error})

    if json_response.get('response_code') == 1:  
        return jsonify({'status': 'completed', 'scan_id': scan_id})

    return jsonify({'status': 'pending'})

@app.route('/results/<scan_id>')
def get_results(scan_id):
    response = VirusTotalAPI.get_report(scan_id)
    json_response, error = handle_response(response)

    if error:
        return render_template('error.html', error=error)

    if json_response.get('response_code') == 1: 
        results = json_response.get('scans', {})
        filename = session.get(scan_id, "N/A")
        return render_template('results.html', results=results, input_value=filename, detection_type='file')
    else:
        return render_template('analysis.html', scan_id=scan_id, waiting=True)

if __name__ == '__main__':
    app.run(debug=True)
