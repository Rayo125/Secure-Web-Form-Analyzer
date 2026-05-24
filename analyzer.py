from flask import Flask, request, jsonify, render_template
from datetime import datetime

app = Flask(__name__)

# Dummy storage
results = []

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/submit', methods=['POST'])
def submit_form():
    form_data = request.json
    analysis = []

    for field, value in form_data.items():
        if not value.strip():
            analysis.append({"field": field, "issue": "Empty field", "severity": "low"})
        elif field.lower() == "password":
            if len(value) < 8:
                analysis.append({"field": field, "issue": "Too short", "severity": "high"})
            elif any(x in value.lower() for x in ["123", "password", "abc"]):
                analysis.append({"field": field, "issue": "Weak password", "severity": "medium"})
        elif "<script>" in value.lower():
            analysis.append({"field": field, "issue": "Unsafe characters", "severity": "high"})

    results.append({"form": form_data.get("formName", "unknown"), "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"), "analysis": analysis})
    return jsonify({"status": "ok", "results": analysis})

@app.route('/dashboard')
def dashboard():
    return jsonify(results)

if __name__ == '_main_':
    app.run(debug=True)