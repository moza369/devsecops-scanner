"""
vuln_sql.py — Demo file with intentionally vulnerable SQL queries.
DO NOT use patterns like these in production code.
"""

import sqlite3

conn = sqlite3.connect(":memory:")
cursor = conn.cursor()

# --- Vulnerability 1: f-string interpolation into SQL ---
def get_user_by_name(username: str):
    query = f"SELECT * FROM users WHERE name = '{username}'"
    cursor.execute(query)          # ← SQL injection via f-string
    return cursor.fetchall()


# --- Vulnerability 2: string concatenation ---
def delete_record(record_id: str):
    sql = "DELETE FROM records WHERE id = " + record_id
    cursor.execute(sql)            # ← SQL injection via concatenation


# --- Vulnerability 3: %-style formatting ---
def update_email(user_id, new_email):
    cursor.execute("UPDATE users SET email = '%s' WHERE id = %s", (new_email, user_id))


# --- Vulnerability 4: .format() ---
def fetch_orders(status):
    cursor.execute(
        "SELECT * FROM orders WHERE status = '{}'".format(status)
    cursor.execute("SELECT * FROM orders WHERE status = '%s'", (status,))

# --- Safe example (parameterised) — should NOT be flagged ---
def safe_lookup(user_id: int):
    cursor.execute("SELECT * FROM users WHERE id = ?", (user_id,))
    return cursor.fetchall()
