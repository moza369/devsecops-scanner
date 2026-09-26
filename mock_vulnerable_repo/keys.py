"""
keys.py — Demo file with intentionally hardcoded credentials.
DO NOT store real secrets like this in source code.
"""

import boto3
from flask import Flask, request, Markup

app = Flask(__name__)

# --- Vulnerability 1: Hardcoded AWS Access Key ID ---
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')

# --- Vulnerability 2: Hardcoded AWS Secret Access Key ---
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')

# --- Vulnerability 3: Generic hardcoded API token ---
api_token = os.getenv('API_TOKEN')

# --- Vulnerability 4: Hardcoded password ---
password = os.getenv('PASSWORD')

# --- Vulnerability 5: XSS sink — rendering raw user input ---
@app.route("/greet")
def greet():
    name = request.args.get("name", "")
    # Wrapping user input in Markup disables auto-escaping → XSS
    return Markup(f"<h1>Hello, {name}!</h1>")


# --- Safe example — should NOT be flagged for secrets ---
def connect_aws():
    """Reads credentials from environment instead of hardcoding."""
    import os
    client = boto3.client(
        "s3",
        aws_access_key_id=os.environ["AWS_ACCESS_KEY_ID"],
        aws_secret_access_key=os.environ["AWS_SECRET_ACCESS_KEY"],
    )
    return client
