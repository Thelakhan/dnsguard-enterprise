import os
import yaml
from flask import Flask, render_template, request, jsonify
from werkzeug.utils import secure_filename
from dnstd.parser import LogParser
from dnstd.detector import DNSTunnelDetector

app = Flask(__name__)

# Use /tmp directory if running on serverless (like Vercel), otherwise use local uploads folder
UPLOAD_FOLDER = '/tmp' if os.path.exists('/tmp') else 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = 200 * 1024 * 1024

RULES_FILE = 'rules.yaml'
with open(RULES_FILE, 'r') as f:
    config = yaml.safe_load(f)
detector = DNSTunnelDetector(config)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/api/rules', methods=['GET'])
def get_rules():
    with open(RULES_FILE, 'r') as f:
        return jsonify(yaml.safe_load(f))

@app.route('/api/rules', methods=['POST'])
def update_rules():
    new_config = request.json
    with open(RULES_FILE, 'w') as f:
        yaml.dump(new_config, f, default_flow_style=False)
    detector.update_config(new_config)
    return jsonify({"status": "success", "message": "Rules updated successfully."})

@app.route('/api/upload', methods=['POST'])
def upload_files():
    if 'files' not in request.files:
        return jsonify({'error': 'No file part'}), 400
        
    files = request.files.getlist('files')
    if not files or files[0].filename == '':
        return jsonify({'error': 'No selected files'}), 400
        
    all_records = []
    processed_files = 0
    
    for file in files:
        if file:
            filename = secure_filename(file.filename)
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            file.save(filepath)
            try:
                parser = LogParser(filepath)
                records = parser.parse()
                all_records.extend(records)
                processed_files += 1
            except Exception as e:
                if os.path.exists(filepath): 
                    os.remove(filepath)
                return jsonify({'error': f'Parser error on {filename}: PCAP files require local system drivers. Please upload a .csv log file on Vercel.'}), 500
            finally:
                if os.path.exists(filepath):
                    os.remove(filepath)
                    
    if not all_records:
        return jsonify({'error': 'No valid DNS records found. Please upload a valid CSV log file.'}), 400
        
    try:
        results = detector.analyze(all_records)
        results['processed_files_count'] = processed_files
        return jsonify(results)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True, port=5000)
