from flask import Flask, render_template, request, jsonify
import validators
import re
from url_detector import URLDetector

app = Flask(__name__)
detector = URLDetector()

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/check-url', methods=['POST'])
def check_url():
    data = request.get_json()
    url = data.get('url', '')
    
    if not url:
        return jsonify({'error': 'URL is required'}), 400
    
    if not validators.url(url):
        return jsonify({'error': 'Invalid URL format'}), 400
    
    result = detector.analyze_url(url)
    
    return jsonify(result)

if __name__ == '__main__':
    app.run(debug=True, port=5000)
