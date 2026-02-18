from flask import Flask, render_template, request, redirect, session, url_for, send_file, jsonify
import sqlite3
import os
import hashlib
from werkzeug.security import generate_password_hash, check_password_hash
import pickle
import io
import mimetypes
import time
from eeaes_files import encrypt_file, decrypt_file
from eeaes import eeaes_encrypt, eeaes_decrypt

app = Flask(__name__)
app.secret_key = "supersecretkey"

DB = "database.db"
UPLOAD_FOLDER = "uploads"
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

def init_db():
    with sqlite3.connect(DB) as conn:
        conn.execute("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE,
            email TEXT,
            password TEXT
        )
        """)

        conn.execute("""
        CREATE TABLE IF NOT EXISTS messages(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT,
            receiver TEXT,
            content BLOB,
            filename TEXT,
           timestamp DATETIME DEFAULT (datetime('now', '+5 hours', '+30 minutes'))
        )
        """)

init_db()

def derive_key_from_user(username):
    with sqlite3.connect(DB) as conn:
        result = conn.execute("SELECT password FROM users WHERE username=?",(username,)).fetchone()
        if result is None:
            raise ValueError(f"User '{username}' not found")
        pwd_hash = result[0]

    return pwd_hash

@app.route("/")
def landing():
    return render_template("landing.html")

@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        u = request.form["username"]
        e = request.form["email"]
        p = request.form["password"]

        p_hash = generate_password_hash(p)

        try:
            with sqlite3.connect(DB) as conn:
                conn.execute("INSERT INTO users(username, email, password) VALUES(?, ?, ?)",(u, e, p_hash))
            return redirect("/login")
        except sqlite3.IntegrityError:
            return "Username already exists!"
        except Exception as e:
            return f"Error: {str(e)}"

    return render_template("signup.html")

@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        u = request.form["username"]
        p = request.form["password"]

        with sqlite3.connect(DB) as conn:
            result = conn.execute("SELECT password FROM users WHERE username=?",(u,)).fetchone()

        if result and check_password_hash(result[0], p):
            session["user"] = u
            return redirect("/dashboard")
        else:
            return "Invalid credentials!"

    return render_template("login.html")

@app.route("/dashboard")
def dashboard():
    if "user" not in session:
        return redirect("/login")

    current = session["user"]

    with sqlite3.connect(DB) as conn:
        users = conn.execute("SELECT username FROM users WHERE username!=?",(current,) ).fetchall()
        msgs = conn.execute("""SELECT id, sender, receiver, content, filename, timestamp
            FROM messages
            ORDER BY timestamp ASC
        """).fetchall()

    chat = []
    for msg_id, sender, receiver, cipher, fname, ts in msgs:
        try:
            key = derive_key_from_user(current)
            
            if fname:
               
                chat.append({
                    "id": msg_id,
                    "sender": sender,
                    "receiver": receiver,
                    "text": None,
                    "file": fname,
                    "time": ts,
                    "status": "file",
                    "can_decrypt": (receiver == current or sender == current)
                })
            else:
                
                if receiver == current or sender == current:
                    try:
                        cipher = pickle.loads(cipher)
                        decrypted_text = eeaes_decrypt(cipher, key)
                        chat.append({
                            "id": msg_id,
                            "sender": sender,
                            "receiver": receiver,
                            "text": decrypted_text,
                            "file": None,
                            "time": ts,
                            "status": "decrypted",
                            "can_decrypt": True
                        })
                    except Exception as e:
                        print(e)
                        chat.append({
                            "id": msg_id,
                            "sender": sender,
                            "receiver": receiver,
                            "text": "[Encrypted message - not for you]",
                            "file": None,
                            "time": ts,
                            "status": "encrypted",
                            "can_decrypt": False
                        })
                else:
                    chat.append({
                        "id": msg_id,
                        "sender": sender,
                        "receiver": receiver,
                        "text": "[Encrypted message]",
                        "file": None,
                        "time": ts,
                        "status": "encrypted",
                        "can_decrypt": False
                    })
        except Exception as e:
        
            chat.append({
                "id": msg_id,
                "sender": sender,
                "receiver": receiver,
                "text": f"[Error: {str(e)}]",
                "file": fname,
                "time": ts,
                "status": "error",
                "can_decrypt": False
            })

    return render_template(
        "dash1.html",
        users=users,
        chat=chat,
        user=current
    )

@app.route("/view_file/<int:msg_id>")
def view_file(msg_id):
    if "user" not in session:
        return redirect("/login")

    current = session["user"]

    with sqlite3.connect(DB) as conn:
        row = conn.execute("""
            SELECT sender, receiver, content, filename
            FROM messages
            WHERE id = ?
        """, (msg_id,)).fetchone()

        if not row:
            return "Message not found", 404

    sender, receiver, cipher, fname = row
    cipher = pickle.loads(cipher)
    if receiver != current and sender != current:
        return "You are not authorized to view this file", 403
    key = derive_key_from_user(receiver if receiver == current else sender)
    decrypted_data = decrypt_file(cipher, key)
    mime = mimetypes.guess_type(fname)[0] or "application/octet-stream"
    if mime.startswith('text/'):
        try:
            content = decrypted_data.decode('utf-8')
            return f"<pre>{content}</pre>"
        except:
            pass
    return send_file(
        decrypted_data,
        mimetype=mime,
        as_attachment=True,
        download_name=fname
    )
    
@app.route("/send", methods=["POST"])
def send():
    if "user" not in session:
        return redirect("/login")

    sender = session["user"]
    receiver = request.form["receiver"]
    message = request.form.get("message", "")
    file = request.files.get("file")

    if not receiver:
        return "Receiver is required", 400

    try:
        key = derive_key_from_user(receiver)
        
        if file and file.filename:
            file_data = file.read()
            
            if not file_data:
                return "File is empty", 400
            
    
            print("starting file encryption")
            encrypted_data = encrypt_file(file, key)
            blob_data = pickle.dumps(encrypted_data)
            filename = file.filename
            
        else:
            if not message.strip():
                return "Message cannot be empty", 400
            encrypted_data = eeaes_encrypt(message, key)
            blob_data = pickle.dumps(encrypted_data)
            filename = None
        
        with sqlite3.connect(DB) as conn:
            conn.execute(
                "INSERT INTO messages(sender, receiver, content, filename) VALUES(?, ?, ?, ?)",
                (sender, receiver, blob_data, filename)
            )
        
        return redirect("/dashboard")
        
    except Exception as e:
        return f"Error sending message: {str(e)}", 500

@app.route("/delete_message/<int:msg_id>")
def delete_message(msg_id):
    if "user" not in session:
        return redirect("/login")
    
    current = session["user"]
    
    with sqlite3.connect(DB) as conn:
        result = conn.execute(
            "SELECT sender FROM messages WHERE id = ?",
            (msg_id,)
        ).fetchone()
        
        if not result:
            return "Message not found", 404
        
        if result[0] != current:
            return "You can only delete your own messages", 403
        conn.execute("DELETE FROM messages WHERE id = ?", (msg_id,))
    
    return redirect("/dashboard")



@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")

if __name__ == "__main__":
    app.run(debug=True, host='0.0.0.0', port=5000)