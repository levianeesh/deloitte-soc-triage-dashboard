from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib
import re

app = Flask(__name__)
CORS(app)

# Load the new, smarter brain
model = joblib.load('advanced_phishing_model.pkl')

def extract_features(url):
    suspicious_words = ['login', 'verify', 'update', 'secure', 'account']
    return [
        len(url),
        1 if '@' in url else 0,
        1 if re.search(r'\d+\.\d+\.\d+\.\d+', url) else 0,
        url.count('.'), # NEW: Count dots to detect deep subdomains
        1 if any(word in url.lower() for word in suspicious_words) else 0 # NEW: Keyword detection
    ]

@app.route('/analyze', methods=['POST'])
def analyze_url():
    data = request.json
    url = data.get('url', '')
    
    features = extract_features(url)
    
    prediction = model.predict([features])
    risk_score = int(prediction[0])
    
    # Map the array to a dictionary so it looks clean on the React dashboard
    feature_dict = {
        "Length": features[0],
        "Has '@'": features[1],
        "Has IP": features[2],
        "Dot Count": features[3],
        "Suspicious Words": features[4]
    }
    
    return jsonify({"url": url, "risk_score": risk_score, "features": feature_dict})

if __name__ == '__main__':
    app.run(port=5000, debug=True)