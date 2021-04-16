import os, html, re, bcrypt, logging, jwt
from dotenv import load_dotenv
from os.path import join, dirname
from flask import Flask, redirect, url_for, render_template, request, flash, make_response
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime

dotenv_path = join(dirname(__file__), '.env')
load_dotenv(dotenv_path)
csrf = CSRFProtect()


logging.basicConfig(filename='auth_service.log', level=logging.DEBUG, 
    format='%(asctime)s %(levelname)s %(name)s %(threadName)s : %(message)s')

app = Flask(__name__, template_folder='templates')
app.config["SECRET_KEY"] = os.environ.get("APP_SECRET_KEY")
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///" + os.environ.get("DATABASE")
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
csrf.init_app(app)
db = SQLAlchemy(app)

class Users(db.Model):
    ''' Models '''
    __tablename__ = "users"
    id = db.Column("id", db.Integer, primary_key=True) 
    username = db.Column(db.String(30))
    password = db.Column(db.String(100))
    salt =  db.Column(db.String(100))
    login_tries = db.Column(db.Integer)
    last_login = db.Column(db.Integer)
    lock_time = db.Column(db.Integer)

    def __init__(self, username, password, salt, login_tries, last_login):
        self.username = username
        self.password = password
        self.salt = salt
        self.login_tries = login_tries
        self.last_login = last_login

def htmlSafe(text) :
    return html.escape(text)

def isUsernameSafe(username) :
    if re.match(r"^[a-zA-Z0-9 .-]+$", username) :
        return True
    else :
        return False

def isCommonPwd(pwd, file = '10k-most-common.txt') :
    with open('10k-most-common.txt') as f:
        common_pwd = [line.rstrip() for line in f]
    if pwd in common_pwd :
        return True
    else :
        return False

def pwdCheck(pwd):
    # common password check 
    common_pwd = isCommonPwd(pwd)

    # calculating the length
    length_error = len(pwd) < 8 or len(pwd) > 64

    # searching for digits
    digit_error = re.search(r"\d", pwd) is None

    # searching for uppercase
    uppercase_error = re.search(r"[A-Z]", pwd) is None

    # searching for lowercase
    lowercase_error = re.search(r"[a-z]", pwd) is None

    # searching for symbols
    symbol_error = re.search(r"[ !#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', pwd) is None

    # overall result
    password_ok = not ( common_pwd or length_error or digit_error or uppercase_error or lowercase_error or symbol_error )

    return {
        'password_ok' : password_ok,
        'common_pwd' : common_pwd,
        'length_error' : length_error,
        'digit_error' : digit_error,
        'uppercase_error' : uppercase_error,
        'lowercase_error' : lowercase_error,
        'symbol_error' : symbol_error,
    }

def encode_auth_token(self, user_id):
    """
    Generates the Auth Token
    :return: string
    """
    try:
        payload = {
            'exp': datetime.datetime.utcnow() + datetime.timedelta(days=0, seconds=3600),
            'iat': datetime.datetime.utcnow(),
            'sub': user_id
        }
        return jwt.encode(
            payload,
            app.config.get('SECRET_KEY'),
            algorithm='HS256'
        )
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    :param auth_token:
    :return: integer|string
    """
    try:
        payload = jwt.decode(auth_token, app.config.get('SECRET_KEY'))
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'

@app.route("/", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # check safe username
        if isUsernameSafe(username) :
            # perform user check on db
            user = Users.query.filter_by(username=username).first()
            current_time = int(datetime.now().timestamp())
            # TODO: further checks before login
            return render_template("login.html")
        else:
            flash("Bad Username: Please try again")
            return render_template("login.html")
    else:
        return render_template("login.html")

@app.route("/create_acc", methods=["POST", "GET"])
def signUp():
    if request.method == "POST":
            username = request.form.get("username")
            password1 = request.form.get("password1")
            password2 = request.form.get("password2")
            # check safe username
            if not isUsernameSafe(username) :
                flash("Bad Username: Please try again")
                return render_template("create_acc.html") 
            # check username does not exist
            user = Users.query.filter_by(username=username).first()
            if user :
                flash("Bad Username: Please try again")
                return render_template("create_acc.html")

            # passwords should match
            if password1 != password2 :
                flash("Password Input Do Not Match")
                return render_template("create_acc.html")
            
            # password check
            res = pwdCheck(password1)
            if res['password_ok'] :
                salt = bcrypt.gensalt(rounds=16)
                hashed_password = bcrypt.hashpw(password1.encode(), salt)
                current_time = int(datetime.now().timestamp())
                print(username,hashed_password,salt,current_time)
                new_user = Users(username, hashed_password, salt, 0, current_time)
                db.session.add(new_user)
                db.session.commit()
                flash("Your account is successfully created!", "info")
                return redirect(url_for("login"))
            else :
                if res['common_pwd'] :
                    flash('Password chosen is too common, please use something more difficult to guess!')
                else:
                    flash('Password must be between 8 to 64 characters with at least 1 Digit, 1 Upper Case Alphabet, 1 Lower Case Alphabet and 1 Special Character')
                return render_template("create_acc.html")
            
            return render_template("create_acc.html")
    else:
        return render_template("create_acc.html")

if __name__ == "__main__":
    # db.drop_all()
    db.create_all()
    context = ('cert.pem','key.pem')
    app.run(ssl_context=context, debug=True)