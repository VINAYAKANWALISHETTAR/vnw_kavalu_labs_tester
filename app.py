"""
Web Application Security Tester
A modern, user-friendly security testing tool using Requests, Selenium, and Burp Suite integration.

Developed by Vinayaka N Walishettar
"""

__author__ = "Vinayaka N Walishettar"

from flask import Flask, render_template, request, jsonify, send_file, send_from_directory
from datetime import datetime
import json
import os
from core.scanner import SecurityScanner
from core.report_generator import ReportGenerator

app = Flask(__name__)
app.config['SECRET_KEY'] = 'your-secret-key-here'
scanner = SecurityScanner()

@app.route('/fonts/<path:filename>')
def serve_fonts(filename):
    """Serve local font assets."""
    return send_from_directory(os.path.join(app.root_path, 'fonts'), filename)

@app.route('/')
def index():
    """Main dashboard page."""
    return render_template('index.html')

@app.route('/api/scan', methods=['POST'])
def start_scan():
    """Start a security scan."""
    data = request.json
    target_url = data.get('url')
    scan_types = data.get('scan_types', ['all'])
    use_burp = data.get('use_burp', False)
    use_selenium = data.get('use_selenium', True)
    
    if not target_url:
        return jsonify({'error': 'Target URL is required'}), 400
    
    try:
        results = scanner.scan(
            target_url=target_url,
            scan_types=scan_types,
            use_burp=use_burp,
            use_selenium=use_selenium
        )
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/scan/status/<scan_id>')
def scan_status(scan_id):
    """Get scan status."""
    status = scanner.get_scan_status(scan_id)
    return jsonify(status)

@app.route('/api/report/<scan_id>')
def generate_report(scan_id):
    """Generate PDF report."""
    format_type = request.args.get('format', 'pdf')
    try:
        report_path = ReportGenerator.generate_report(scan_id, format_type)
        return send_file(report_path, as_attachment=True)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/history')
def scan_history():
    """Get scan history."""
    history = scanner.get_scan_history()
    return jsonify(history)

if __name__ == '__main__':
    os.makedirs('reports', exist_ok=True)
    os.makedirs('logs', exist_ok=True)
    app.run( host='0.0.0.0', port=5000)
