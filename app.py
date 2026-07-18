import math
import hashlib
from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
import zxcvbn

app = Flask(__name__)
CORS(app)

COMMON_WORDS = ['password', '123456', 'qwerty', 'letmein', 'admin', 'welcome',
                'monkey', 'dragon', 'football', 'iloveyou', 'abc123']

def calc_entropy(pw):
    if not pw:
        return 0
    pool_size = 0
    if any(c.islower() for c in pw): pool_size += 26
    if any(c.isupper() for c in pw): pool_size += 26
    if any(c.isdigit() for c in pw): pool_size += 10
    if any(not c.isalnum() for c in pw): pool_size += 32

    if pool_size == 0:
        return 0
    return round(len(pw) * math.log2(pool_size))

@app.route('/api/health', methods=['GET'])
def health():
    return jsonify({"status": "ok"})

@app.route('/api/analyze', methods=['POST'])
def analyze_password():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Empty password"}), 400

    entropy = calc_entropy(password)
    is_common = any(word in password.lower() for word in COMMON_WORDS)

    zxcvbn_res = zxcvbn.zxcvbn(password)
    score_out_of_four = zxcvbn_res['score']
    score_100 = score_out_of_four * 25

    suggestions = zxcvbn_res['feedback']['suggestions']
    if not suggestions and score_out_of_four < 3:
        suggestions = ["Try adding mixed casing, symbols, or extending length."]

    return jsonify({
        "entropy": entropy,
        "isCommon": is_common,
        "score": score_100,
        "crackTimeEst": zxcvbn_res['crack_times_display']['offline_fast_hashing_1e10_per_second'],
        "suggestions": suggestions
    })

@app.route('/api/check-breach', methods=['POST'])
def check_breach():
    data = request.get_json(silent=True) or {}
    password = data.get('password', '')

    if not password:
        return jsonify({"error": "Empty password"}), 400

    sha1_hash = hashlib.sha1(password.encode('utf-8')).hexdigest().upper()
    prefix = sha1_hash[:5]
    suffix = sha1_hash[5:]

    url = f"https://api.pwnedpasswords.com/range/{prefix}"
    headers = {"User-Agent": "CyberPure-Password-Analyzer"}

    try:
        response = requests.get(url, headers=headers, timeout=5)
        if response.status_code != 200:
            return jsonify({"status": "error", "message": "API Unavailable"}), 502
    except requests.RequestException:
        return jsonify({"status": "error", "message": "Network Timeout"}), 504

    hashes = (line.split(':') for line in response.text.splitlines())
    match_count = 0

    for h_suffix, count in hashes:
        if h_suffix == suffix:
            match_count = int(count)
            break

    if match_count > 0:
        return jsonify({
            "compromised": True,
            "count": match_count,
            "message": f"Exposed in {match_count:,} known data leaks!"
        })
    else:
        return jsonify({
            "compromised": False,
            "count": 0,
            "message": "Safe! Not found in database leaks."
        })