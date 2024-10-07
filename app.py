from flask import Flask, render_template, jsonify, Response, request
from socket import socket, AF_INET, SOCK_STREAM
from datetime import datetime, timedelta
import ipaddress
import json
from urllib.parse import unquote
from concurrent.futures import ThreadPoolExecutor
import subprocess
import os
import pyclamd  # For malware scanning
import pymongo  # For MongoDB integration


app = Flask(__name__)

# ClamAV connection for malware scanning
cd = pyclamd.ClamdNetworkSocket('127.0.0.1', 3310)

client = pymongo.MongoClient("MONGODB URL")
db = client['Detector']  # Database for scan reports
reports_collection = db['reports']


@app.route('/')
def index():
    return render_template('index.html')

@app.route('/scan/ip/<path:target_ip>')
def scan_ip(target_ip):
    decoded_ip = unquote(target_ip)

    if not validate_ip(decoded_ip):
        # Save failed report
        report = {
            'type': 'ip_scan',
            'target_ip': decoded_ip,
            'timestamp': datetime.utcnow(),
            'result': 'Invalid IP address',
            'status': 'failed'
        }
        reports_collection.insert_one(report)
        return jsonify({'error': 'Invalid IP address'}), 400

    def generate():
        try:
            # Add timeout to prevent hanging
            result = subprocess.run(
                ["nmap", "-p", "1-65535", "--max-retries", "1", "--host-timeout", "30s", decoded_ip],
                capture_output=True,
                text=True,
                timeout=35  # Total timeout including buffer
            )

            # Save scan result to MongoDB
            report = {
                'type': 'ip_scan',
                'target_ip': decoded_ip,
                'timestamp': datetime.utcnow(),
                'result': result.stdout if result.returncode == 0 else result.stderr,
                'status': 'success' if result.returncode == 0 else 'failed'
            }
            reports_collection.insert_one(report)

            if result.returncode != 0:
                yield json.dumps({'error': 'Scanning failed', 'details': result.stderr})
            else:
                yield json.dumps({'result': result.stdout})

        except subprocess.TimeoutExpired:
            error_msg = f"Scan timeout for IP: {decoded_ip}"
            # Save timeout report
            report = {
                'type': 'ip_scan',
                'target_ip': decoded_ip,
                'timestamp': datetime.utcnow(),
                'result': error_msg,
                'status': 'failed'
            }
            reports_collection.insert_one(report)
            yield json.dumps({'error': error_msg})

    return Response(generate(), mimetype='text/event-stream')

@app.route('/ip-scan')
def ip_scan():
    return render_template('ip_scan.html')





# Route for malware scanning
@app.route('/scan/malware', methods=['POST'])
def scan_malware():
    if 'file' not in request.files:
        return jsonify({'error': 'No file part in the request'}), 400

    file = request.files['file']

    if file.filename == '':
        return jsonify({'error': 'No selected file'}), 400

    # Save the file temporarily for scanning
    file_path = os.path.join('/tmp', file.filename)
    file.save(file_path)

    # Perform malware scan using ClamAV
    try:
        scan_result = cd.scan_file(file_path)
        if scan_result is None:
            result = {'status': 'clean', 'message': 'No malware found'}
        else:
            result = {'status': 'infected', 'message': 'Malware detected', 'details': scan_result}
    except Exception as e:
        result = {'status': 'error', 'message': str(e)}

    # Clean up the temporary file after scanning
    os.remove(file_path)

    # Save report in MongoDB
    report = {
        'type': 'malware_scan',
        'filename': file.filename,
        'result': result
    }
    reports_collection.insert_one(report)

    return jsonify(result)


@app.route('/malware-scan')
def malware_scan():
    return render_template('malware_scan.html')


@app.route('/api/reports')
def get_reports():
    page = int(request.args.get('page', 1))
    type_filter = request.args.get('type', 'all')
    time_filter = request.args.get('time', 'all')
    status_filter = request.args.get('status', 'all')
    
    # Build query based on filters
    query = {}
    
    if type_filter != 'all':
        query['type'] = type_filter
        
    if time_filter != 'all':
        time_ranges = {
            '24h': timedelta(hours=24),
            '7d': timedelta(days=7),
            '30d': timedelta(days=30)
        }
        if time_filter in time_ranges:
            query['timestamp'] = {
                '$gte': datetime.utcnow() - time_ranges[time_filter]
            }

    # Handle status filtering for both types of scans
    if status_filter != 'all':
        if status_filter == 'infected':
            # For malware scans with infected status
            query['$or'] = [
                {'result.status': 'infected'},  # For malware scans
                {'status': 'infected'}          # For legacy format
            ]
        else:
            # For success/failed status (mainly IP scans)
            query['$or'] = [
                {'status': status_filter},           # For IP scans
                {'result.status': status_filter}     # For malware scans
            ]
    
    # Calculate pagination
    per_page = 10
    skip = (page - 1) * per_page
    
    # Get total count for pagination
    total = reports_collection.count_documents(query)
    
    # Get paginated results
    reports = list(reports_collection.find(
        query,
        {'_id': 0}  # Exclude MongoDB ID
    ).sort('timestamp', -1).skip(skip).limit(per_page))
    
    return jsonify({
        'reports': reports,
        'total': total
    })
    

@app.route('/reports')
def reports():
    return render_template('reports.html')

@app.route('/settings')
def settings():
    return render_template('settings.html')

@app.route('/login')
def login():
    return render_template('login.html')

def validate_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True)
