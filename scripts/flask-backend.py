from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import hashlib
import time
import os
from werkzeug.utils import secure_filename

app = Flask(__name__)
CORS(app)

# Your VirusTotal API key - set this as an environment variable
VIRUSTOTAL_API_KEY = os.getenv('VIRUSTOTAL_API_KEY', '047673d4aa55dfb43497a72b4f70d126fc38b9bac2a4abaeace83275ea370699')
VIRUSTOTAL_BASE_URL = 'https://www.virustotal.com/vtapi/v2'

def get_virustotal_headers():
    return {
        'apikey': VIRUSTOTAL_API_KEY
    }

@app.route('/api/scan/url', methods=['POST'])
def scan_url():
    try:
        url = request.form.get('url')
        if not url:
            return jsonify({'error': 'No URL provided'}), 400
        
        # Submit URL to VirusTotal
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'url': url
        }
        
        response = requests.post(f'{VIRUSTOTAL_BASE_URL}/url/scan', data=params)
        scan_result = response.json()
        
        if response.status_code != 200:
            return jsonify({'error': 'VirusTotal API error'}), 500
        
        # Wait a moment then get the report
        time.sleep(2)
        
        report_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': url
        }
        
        report_response = requests.get(f'{VIRUSTOTAL_BASE_URL}/url/report', params=report_params)
        report_data = report_response.json()
        
        return jsonify(report_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/file', methods=['POST'])
def scan_file():
    try:
        if 'file' not in request.files:
            return jsonify({'error': 'No file provided'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': 'No file selected'}), 400
        
        # Submit file to VirusTotal
        files = {'file': (file.filename, file.stream, file.content_type)}
        params = {'apikey': VIRUSTOTAL_API_KEY}
        
        response = requests.post(f'{VIRUSTOTAL_BASE_URL}/file/scan', files=files, params=params)
        scan_result = response.json()
        
        if response.status_code != 200:
            return jsonify({'error': 'VirusTotal API error'}), 500
        
        # Wait for scan to complete then get report
        time.sleep(5)
        
        report_params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'resource': scan_result.get('sha256', scan_result.get('resource'))
        }
        
        report_response = requests.get(f'{VIRUSTOTAL_BASE_URL}/file/report', params=report_params)
        report_data = report_response.json()
        
        return jsonify(report_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/domain', methods=['POST'])
def scan_domain():
    try:
        domain = request.form.get('domain')
        if not domain:
            return jsonify({'error': 'No domain provided'}), 400
        
        # Get domain report from VirusTotal
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'domain': domain
        }
        
        response = requests.get(f'{VIRUSTOTAL_BASE_URL}/domain/report', params=params)
        report_data = response.json()
        
        if response.status_code != 200:
            return jsonify({'error': 'VirusTotal API error'}), 500
        
        return jsonify(report_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/email', methods=['POST'])
def scan_email():
    try:
        email = request.form.get('email')
        if not email:
            return jsonify({'error': 'No email provided'}), 400
        
        # Extract domain from email
        domain = email.split('@')[1] if '@' in email else email
        
        # Get domain report from VirusTotal
        params = {
            'apikey': VIRUSTOTAL_API_KEY,
            'domain': domain
        }
        
        response = requests.get(f'{VIRUSTOTAL_BASE_URL}/domain/report', params=params)
        report_data = response.json()
        
        if response.status_code != 200:
            return jsonify({'error': 'VirusTotal API error'}), 500
        
        # Add email-specific information
        report_data['email'] = email
        report_data['domain'] = domain
        
        return jsonify(report_data)
        
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(host='127.0.0.1', port=5328, debug=True)
