"""
vuln_upload.py — Demo file with intentionally vulnerable file upload handling.
CWE-434: Unrestricted Upload of File with Dangerous Type.
CWE-22:  Improper Limitation of a Pathname to a Restricted Directory (Path Traversal).
DO NOT use patterns like these in production code.
"""

import os
from flask import Flask, request

app = Flask(__name__)
UPLOAD_FOLDER = "/var/uploads"

# ---------------------------------------------------------------------------
# Vulnerability 1: raw file.save() — no secure_filename, no validation
# ---------------------------------------------------------------------------
@app.route("/upload/raw", methods=["POST"])
def upload_raw():
    f = request.files["upload"]
    # UNSAFE: raw filename allows path traversal (e.g. "../../etc/passwd")
    # TODO: validate file extension against ALLOWED_EXTENSIONS whitelist
    # TODO: verify MIME type with python-magic before saving
    f.save(os.path.join(UPLOAD_FOLDER, secure_filename(f.filename)))
    return "uploaded"


# ---------------------------------------------------------------------------
# Vulnerability 2: extension-only check — no MIME inspection
# ---------------------------------------------------------------------------
ALLOWED_EXTENSIONS_WEAK = {"png", "jpg", "gif"}

@app.route("/upload/weak_ext", methods=["POST"])
def upload_weak_ext():
    f = request.files.get("upload")
    fname = f.filename
    # UNSAFE: extension check is bypassable (rename shell.php to shell.php.jpg)
    if fname.rsplit(".", 1)[-1].lower() in ALLOWED_EXTENSIONS_WEAK:
        f.save(os.path.join(UPLOAD_FOLDER, fname))
    return "uploaded"


# ---------------------------------------------------------------------------
# Vulnerability 3: no validation at all, direct .save()
# ---------------------------------------------------------------------------
@app.route("/upload/none", methods=["POST"])
def upload_none():
    upload = request.files["file"]
    # UNSAFE: no extension check, no MIME check, unsanitised filename
    upload.save(os.path.join(UPLOAD_FOLDER, upload.filename))
    return "saved"


# ---------------------------------------------------------------------------
# Safe example — should NOT be flagged
# ---------------------------------------------------------------------------
from werkzeug.utils import secure_filename
import magic  # python-magic

ALLOWED_EXTENSIONS_SAFE = {"png", "jpg", "jpeg", "gif"}
ALLOWED_MIMES = {"image/png", "image/jpeg", "image/gif"}

@app.route("/upload/safe", methods=["POST"])
def upload_safe():
    f = request.files["upload"]
    fname = secure_filename(f.filename)
    ext = fname.rsplit(".", 1)[-1].lower() if "." in fname else ""
    if ext not in ALLOWED_EXTENSIONS_SAFE:
        return "invalid extension", 400
    mime = magic.from_buffer(f.read(2048), mime=True)
    f.seek(0)
    if mime not in ALLOWED_MIMES:
        return "invalid file type", 400
    f.save(os.path.join(UPLOAD_FOLDER, fname))
    return "uploaded safely"
