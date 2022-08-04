import os
import pathlib
from flask import (
    Flask, flash, g, redirect, render_template, request, url_for
)
import requests
from flask import session, abort
from google.oauth2 import id_token
from google_auth_oauthlib.flow import Flow
from pip._vendor import cachecontrol
import google.auth.transport.requests

import os

from werkzeug.utils import secure_filename
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
import sqlite3



import click
from flask import current_app, g
from flask.cli import with_appcontext

app = Flask("Google Login App")


basedir = os.path.abspath(os.path.dirname(__file__))





UPLOAD_FOLDER = 'static/uploads'
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'gif'}



limiter = Limiter(app, key_func=get_remote_address)

app.secret_key = "xcvx.com"




 


app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
os.environ["OAUTHLIB_INSECURE_TRANSPORT"] = "1"

GOOGLE_CLIENT_ID = "123enterhere.apps.googleusercontent.com"
client_secrets_file = os.path.join(pathlib.Path(__file__).parent, "client_secret.json")

flow = Flow.from_client_secrets_file(
    client_secrets_file=client_secrets_file,
    scopes=["https://www.googleapis.com/auth/userinfo.profile", "https://www.googleapis.com/auth/userinfo.email", "openid"],
    redirect_uri="http://127.0.0.1:5000/callback"
)



def get_db():
    conn = sqlite3.connect('database.db')
    conn.row_factory = sqlite3.Row
    return conn




def login_is_required(function):
    def wrapper1(*args, **kwargs):
        if "google_id" not in session:
            flash("login Required")
            return redirect("/login")  # Authorization required
        else:
            return function()

    return wrapper1


@app.route("/login")
def login():
    authorization_url, state = flow.authorization_url()
    session["state"] = state
    return redirect(authorization_url)


@app.route("/callback")
def callback():
    flow.fetch_token(authorization_response=request.url)

    if not session["state"] == request.args["state"]:
        abort(500)  # State does not match!

    credentials = flow.credentials
    request_session = requests.session()
    cached_session = cachecontrol.CacheControl(request_session)
    token_request = google.auth.transport.requests.Request(session=cached_session)

    id_info = id_token.verify_oauth2_token(
        id_token=credentials._id_token,
        request=token_request,
        audience=GOOGLE_CLIENT_ID
    )

    session["google_id"] = id_info.get("sub")
    session["name"] = id_info.get("name")
    
    return redirect("/upload")


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/")
def index():
    db = get_db()
    user = get_db().execute(
            'SELECT * FROM user WHERE username = ?', (session['name'],)
        ).fetchone()
    if user is None:
        db.execute(
                    "INSERT INTO user (username, password) VALUES (?, ?)",
                    (session["name"], session["google_id"]),
                )
        db.commit()
   
    posts = db.execute(
        'SELECT p.id, img, created, author_id, username'
        ' FROM post p JOIN user u ON p.author_id = u.id'
        ' ORDER BY created DESC'
    ).fetchall()
    
    return render_template('blog/index.html', posts=posts)

def allowed_file(filename):
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


@app.before_request
def load_logged_in_user():
    user_name = session['name']

    if user_name is None:
        g.user = None
    else:
        g.user = get_db().execute(
            'SELECT * FROM user WHERE username = ?', (user_name,)
        ).fetchone()

@app.route("/upload", methods=['GET', 'POST'])
@login_is_required
@limiter.limit("5/minute")
def create():
    if request.method == 'POST':
        
        if 'file' not in request.files:
            flash('No file part')
            return redirect(request.url)
        file = request.files['file']
        # If the user does not select a file, the browser submits an
        # empty file without a filename.
        if file.filename == '':
            flash('No selected file')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = secure_filename(file.filename)
            file.save(os.path.join(basedir, app.config['UPLOAD_FOLDER'], filename))
        
            db = get_db()
            db.execute(
                'INSERT INTO post (img, author_id)'
                ' VALUES (?, ?)',
                ('static/uploads/'+file.filename, g.user['id'])
            )
            db.commit()
            
            return redirect("/")

    return render_template('blog/create.html')  










if __name__ == "__main__":
    app.run(debug=True)
