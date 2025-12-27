from flask import Flask, request, render_template_string
import re
from datetime import datetime

app = Flask(__name__)

# ---------------- CONFIG ----------------

PHISHING_KEYWORDS = {
    "urgent": "Creates panic to force quick action without verification.",
    "verify": "Often used to trick users into confirming credentials.",
    "account suspended": "Fear-based manipulation tactic.",
    "click here": "Encourages unsafe interaction with malicious links.",
    "reset password": "Common credential harvesting attempt.",
    "security alert": "Impersonates trusted authority.",
    "confirm identity": "Used to steal personal information.",
    "limited time": "Applies artificial urgency.",
    "act now": "Psychological pressure technique.",
    "free": "Lures victims with fake rewards."
}

SUSPICIOUS_TLDS = [".tk", ".xyz", ".ru", ".cn", ".top", ".ga"]

# ---------------- ANALYSIS ENGINE ----------------

def analyze_content(text):
    score = 0
    findings = []
    explanation = []

    content = text.lower()

    explanation.append(
        "The provided content was analyzed using rule-based phishing detection "
        "focused on social engineering and URL manipulation techniques."
    )

    # ---- URL Analysis ----
    if "http://" in content or "https://" in content:
        explanation.append(
            "A URL was detected in the message. URL-based risk analysis was performed."
        )

        if len(content) > 80:
            score += 15
            findings.append("Unusually long URL detected")
            explanation.append(
                "Long URLs are commonly used to hide malicious domains or parameters."
            )

        if "@" in content:
            score += 15
            findings.append("URL contains '@' redirection symbol")
            explanation.append(
                "The '@' symbol can redirect users to a different domain than expected."
            )

        if re.search(r"\d+\.\d+\.\d+\.\d+", content):
            score += 20
            findings.append("IP address used instead of domain name")
            explanation.append(
                "Legitimate organizations rarely use raw IP addresses in links."
            )

        if content.startswith("http://"):
            score += 10
            findings.append("URL uses insecure HTTP instead of HTTPS")
            explanation.append(
                "Lack of HTTPS encryption reduces trust and increases risk."
            )

        for tld in SUSPICIOUS_TLDS:
            if tld in content:
                score += 15
                findings.append(f"Suspicious top-level domain detected ({tld})")
                explanation.append(
                    "Certain TLDs are frequently abused in phishing campaigns."
                )

    # ---- Language & Social Engineering ----
    for keyword, meaning in PHISHING_KEYWORDS.items():
        if keyword in content:
            score += 5
            findings.append(f"Phishing-related phrase detected: '{keyword}'")
            explanation.append(meaning)

    # ---- Psychological Pressure ----
    if text.count("!") >= 3:
        score += 5
        findings.append("Excessive urgency indicators detected")
        explanation.append(
            "Attackers often use urgency to bypass rational decision-making."
        )

    score = min(score, 100)

    # ---- Risk Level ----
    if score <= 30:
        level = "LOW"
        recommendation = (
            "The content appears safe. No immediate action is required, "
            "but continued awareness is recommended."
        )
        color = "#00ff88"
    elif score <= 60:
        level = "MEDIUM"
        recommendation = (
            "Potential phishing indicators detected. Verify the sender, "
            "avoid clicking links, and confirm authenticity."
        )
        color = "#ffd000"
    else:
        level = "HIGH"
        recommendation = (
            "High-confidence phishing indicators detected. "
            "Do not interact with this content. Block and report immediately."
        )
        color = "#ff3b3b"

    return score, level, findings, explanation, recommendation, color

# ---------------- ROUTE ----------------

@app.route("/", methods=["GET", "POST"])
def index():
    result = None

    if request.method == "POST":
        content = request.form.get("content", "")

        score, level, findings, explanation, recommendation, color = analyze_content(content)

        result = {
            "score": score,
            "level": level,
            "findings": findings,
            "explanation": explanation,
            "recommendation": recommendation,
            "color": color,
            "time": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

    return render_template_string(TEMPLATE, result=result)

# ---------------- UI ----------------

TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
<title>BitBytes | Phishing Risk Analyzer</title>
<style>
body {
    background:#02020a;
    color:white;
    font-family:Segoe UI;
    padding:30px;
}
textarea {
    width:100%;
    padding:14px;
    background:#020215;
    color:white;
    border:1px solid #00ffd5;
}
button {
    padding:12px 30px;
    border:2px solid #00ffd5;
    background:transparent;
    color:#00ffd5;
    cursor:pointer;
}
.panel {
    margin-top:30px;
    padding:25px;
    background:#05051f;
}
</style>
</head>
<body>

<h1 style="color:#00ffd5;">BitBytes</h1>
<p>Be the Best Version of Yourself</p>

<form method="post">
<h3>Message / URL Content</h3>
<textarea name="content" rows="6"
placeholder="Paste email content, SMS, or URL here..."></textarea>
<br><br>
<button type="submit">Analyze Phishing Risk</button>
</form>

{% if result %}
<div class="panel">
<h2 style="color:{{result.color}}">
{{result.score}} / 100 — {{result.level}} RISK
</h2>

<p><b>Scan Time:</b> {{result.time}}</p>

<h3>🔍 Technical Findings</h3>
<ul>
{% for f in result.findings %}
<li>{{f}}</li>
{% endfor %}
</ul>

<h3>🧠 Analyst Explanation</h3>
<ul>
{% for e in result.explanation %}
<li>{{e}}</li>
{% endfor %}
</ul>

<h3>📌 Recommendation</h3>
<p>{{result.recommendation}}</p>
</div>
{% endif %}

</body>
</html>
"""

if __name__ == "__main__":
    app.run(debug=True)
