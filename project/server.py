import os, re, bcrypt, logging, jwt , random, hashlib
from dotenv import load_dotenv
from os.path import join, dirname
from flask import Flask, redirect, url_for, render_template, request, flash, make_response, jsonify, g
from flask_wtf.csrf import CSRFProtect
from flask_sqlalchemy import SQLAlchemy
from datetime import datetime, timedelta
from time import sleep

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
    """ Model for Users """
    __tablename__ = "users"
    id = db.Column("id", db.Integer, primary_key=True, autoincrement=True) 
    username = db.Column(db.String(30))
    password = db.Column(db.String(100))
    salt =  db.Column(db.String(100))
    login_tries = db.Column(db.Integer)
    last_login = db.Column(db.Integer)
    lock_time = db.Column(db.Integer)

    def __init__(self, username, password, salt, login_tries, last_login, lock_time):
        self.username = username
        self.password = password
        self.salt = salt
        self.login_tries = login_tries
        self.last_login = last_login
        self.lock_time = lock_time

class RevokedTokens(db.Model) :
    """ Model for Revoked JWTs """
    ___tablename__ = "revoked_jwts"
    id = db.Column("id", db.Integer, primary_key = True, autoincrement = True)
    revoked_token = db.Column(db.String(128))
    revoked_time = db.Column(db.Integer)
    def __init__(self, revoked_token, revoked_time) :
        self.revoked_token = revoked_token
        self.revoked_time = revoked_time

def md5(fname):
    """
    Helper function to get md5 hash checksum of a file
    Param: filename to generate md5 hash checksum
    Return: String
    """
    hash_md5 = hashlib.md5()
    with open(fname, "rb") as f:
        for chunk in iter(lambda: f.read(4096), b""):
            hash_md5.update(chunk)
    return hash_md5.hexdigest()

def isUsernameSafe(username) :
    """
    Checks if username provided follows the rule : alpha-numeric and '-'
    Returns : Boolean
    """
    if re.match(r"^[a-zA-Z0-9 .-]+$", username) :
        return True
    else :
        return False

def isCommonPwd(pwd) :
    """
    Helper function to check for common password from a txt file
    Param: Password to check
    Return: Boolean
    """
    file = './10k-most-common.txt'
    assert md5(file) == "0efee504c93d65b37a267005657a7785", "file hash does not match"
    with open(file) as f:
        common_pwd = [line.rstrip() for line in f]
    if pwd in common_pwd :
        return True
    else :
        return False
    

def pwdCheck(pwd):
    """
    Helper function to check for validity of a password provided before it is accepted
    to be use for the account.
    Param: Password to check
    Return: Dictionary of key-value boolean pairs of the check result
    """
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
    symbol_error = re.search(r"[ @!#$%&'()*+,-./[\\\]^_`{|}~"+r'"]', pwd) is None

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

def encode_auth_token(user_id):
    """
    Generates the Auth Token
    Param: user_id 
    Return : string
    """
    jwt_secret = os.environ.get("JWT_SECRET_KEY")

    payload = {
        'exp': datetime.utcnow() + timedelta(days=0, seconds=3600),
        'iat': datetime.utcnow(),
        'sub': user_id
        }
    try:
        token = jwt.encode(
            payload,
            jwt_secret,
            algorithm='HS256'
        )
        return token
    except Exception as e:
        return e

def decode_auth_token(auth_token):
    """
    Decodes the auth token
    Param: auth_token
    Return: integer|string
    """
    jwt_secret = os.environ.get("JWT_SECRET_KEY")

    try:
        payload = jwt.decode(auth_token, jwt_secret, algorithms=['HS256'],
        options={"verify_signature": True})
        return payload['sub']
    except jwt.ExpiredSignatureError:
        return 'Signature expired. Please log in again.'
    except jwt.InvalidTokenError:
        return 'Invalid token. Please log in again.'


""" Routes """

"""
Login Page
"""
@app.route("/", methods=["POST", "GET"])
def login():
    if request.method == "POST":
        username = request.form.get("username")
        password = request.form.get("password")
        # check safe username
        if isUsernameSafe(username) :
            # perform user check on db
            user = Users.query.filter_by(username=username).first() 
            if user :
                current_time = int(datetime.now().timestamp())

                # check if account is locked out 
                if user.login_tries > 5  and current_time - user.lock_time < (5*60) :
                    flash('User Account is Locked Out for ' + str(user.lock_time + (5*60) - current_time) + ' sec', "error")
                    return redirect(url_for("login"))
                
                # check password provided vs stored
                hash_prov_passwd = bcrypt.hashpw(password.encode(), user.salt)
                if not hash_prov_passwd == user.password :
                    # wrong password provided
                    user.login_tries += 1
                    if user.login_tries == 5 :
                        flash('Account Locked For 5min', "error")
                        app.logger.warning("[login]Account for : " + user.username)
                        user.lock_time = int(datetime.now().timestamp())
                        db.session.commit()
                        sleep(random.uniform(0, 0.5))
                        return redirect(url_for("login"))
                    else:   
                        flash('Please try again', "error")
                        app.logger.warning("[login]Wrong password provided for : " + user.username)
                        db.session.commit()
                        sleep(random.uniform(0, 0.5))
                        return redirect(url_for("login"))
                else : 
                    # correct password provided
                    sleep(random.uniform(0, 0.5))
                    try:
                        auth_token = encode_auth_token(user.id)
                        if auth_token:
                            user.login_tries = 0
                            user.last_login = int(datetime.now().timestamp())
                            db.session.commit()
                            response = make_response(redirect(url_for("dashboard")))
                            response.set_cookie('auth', auth_token, httponly=True, secure=True)
                            flash("Successfully Logged In", "success")
                            return response
                    except Exception as e:
                            print(e)
                            response = make_response(redirect(url_for("login")))
                            return response, 500
            else :
                # no such user
                flash("Please try again", "error")
                app.logger.warning("[login]User does not exist : " + username)
                sleep(random.uniform(4, 4.5)) # padded time to take into account hashing time for bcrypt
                return redirect(url_for("login"))
        else:
            # unsafe username
            flash("Please try again", "error")
            app.logger.warning("Unsafe username provided : " + username)
            sleep(random.uniform(4, 4.5)) # padded time to take into account hashing time for bcrypt
            return redirect(url_for("login"))
    else:
        return render_template("login.html")

"""
Create Account Page
"""
@app.route("/create_acc", methods=["POST", "GET"])
def signUp():
    if request.method == "POST":
            username = request.form.get("username")
            password1 = request.form.get("password1")
            password2 = request.form.get("password2")
            # check safe username
            if not isUsernameSafe(username) or len(username) > 30 :
                flash("Username should contain only Alpha-numeric characters and hypens and length no more than 30 characters", "error")
                return redirect(url_for("signUp"))
            # check username does not exist
            user = Users.query.filter_by(username=username).first()
            if user :
                flash("Please try again (User Exists)", "error")
                return redirect(url_for("signUp"))

            # passwords should match
            if password1 != password2 :
                flash("Passwords do not matchh", "error")
                return redirect(url_for("signUp"))
            
            # password check
            res = pwdCheck(password1)
            if res['password_ok'] :
                salt = bcrypt.gensalt(rounds=16)
                hashed_password = bcrypt.hashpw(password1.encode(), salt)
                new_user = Users(username, hashed_password, salt, 0, 0, 0)
                db.session.add(new_user)
                db.session.commit()
                flash("Your account is successfully created!", "success")
                return redirect(url_for("login"))
            else :
                if res['common_pwd'] :
                    flash('Password chosen is too common, please use something more difficult to guess!', "error")
                else:
                    flash('Password must be between 8 to 64 characters with at least 1 Digit, 1 Upper Case Alphabet, 1 Lower Case Alphabet and 1 Special Character' , "error")
                return render_template("create_acc.html")
            
            return redirect(url_for("signUp"))
    else:
        return render_template("create_acc.html")

"""
User Dashboard (after login) Page
"""
@app.route("/dashboard", methods=["GET"])
def dashboard():
    auth_token = request.cookies.get('auth')
    if auth_token is None or RevokedTokens.query.filter_by(revoked_token=auth_token).first():
        g.user = None
        flash("Please log in", "error")
        return redirect(url_for("login"))
    else:
        res = decode_auth_token(auth_token)
        if isinstance(res, int) :
            g.user = Users.query.filter_by(id=res).first()
            return render_template("dashboard.html")
        else :
            g.user = None
            flash(res, "error")
            return redirect(url_for("login"))

"""
End-point that handles logout logic
"""
@app.route("/logout", methods=["GET"])
def logout():
    #print("logout")
    auth_token = request.cookies.get('auth').strip()
    #print(auth_token)
    if auth_token is None or RevokedTokens.query.filter_by(revoked_token=auth_token).first():
        flash("Please log in", "error")
        return redirect(url_for("login"))
    else:
        new_revoke = RevokedTokens(auth_token, int(datetime.now().timestamp()))
        db.session.add(new_revoke)
        db.session.commit()
        flash("Successfully Logged Out", "success")
        return redirect(url_for("login"))

"""
Reset Password Page
"""
@app.route("/reset_pwd", methods=["POST", "GET"])
def resetPwd():
    if request.method == "POST":
            username = request.form.get("username")
            old_pass = request.form.get("password0")
            password1 = request.form.get("password1")
            password2 = request.form.get("password2")
            # check safe username
            if isUsernameSafe(username) :
                # perform user check on db
                user = Users.query.filter_by(username=username).first() 
                if user :
                    # check if account is locked out 
                    if user.login_tries > 5  and current_time - user.lock_time < (5*60) :
                        flash('[pwd_reset]User Account is Locked Out for ' + str(user.lock_time + (5*60) - current_time) + ' sec', "error")
                        return redirect(url_for("resetPwd"))
                    
                    # check password provided vs stored
                    hash_prov_passwd = bcrypt.hashpw(old_pass.encode(), user.salt)
                    if not hash_prov_passwd == user.password :
                        # wrong password provided
                        user.login_tries += 1
                        if user.login_tries == 5 :
                            flash('Account Locked For 5min', "error")
                            user.lock_time = int(datetime.now().timestamp())
                            db.session.commit()
                            sleep(random.uniform(0, 0.5))
                            return redirect(url_for("resetPwd"))
                        else:   
                            flash('Please try again', "error")
                            app.logger.warning("[pwd_reset]Wrong password provided for : " + user.username)
                            db.session.commit()
                            sleep(random.uniform(0, 0.5))
                            return redirect(url_for("resetPwd"))
                    else : 
                        # correct password provided
                        user.login_tries = 0
                        # passwords should match
                        if password1 != password2 :
                            flash("Passwords do not matchh", "error")
                            return redirect(url_for("resetPwd"))
                        
                        # password check
                        res = pwdCheck(password1)
                        if res['password_ok'] :
                            salt = bcrypt.gensalt(rounds=16)
                            hashed_password = bcrypt.hashpw(password1.encode(), salt)
                            user.salt = salt
                            user.password = hashed_password
                            db.session.commit()
                            auth_token = request.cookies.get('auth').strip()
                            if auth_token is not None :
                                new_revoke = RevokedTokens(auth_token, int(datetime.now().timestamp()))
                                db.session.add(new_revoke)
                                db.session.commit()
                            flash("Your password is successfully resetted! Please log in again.", "success")
                            app.logger.warning("Password reset successful for : " + user.username)
                            return redirect(url_for("login"))
                        else :
                            if res['common_pwd'] :
                                flash('Password chosen is too common, please use something more difficult to guess!', "error")
                            else:
                                flash('Password must be between 8 to 64 characters with at least 1 Digit, 1 Upper Case Alphabet, 1 Lower Case Alphabet and 1 Special Character' , "error")
                            return render_template("reset.html")
                else :
                    #no such user
                    flash("Please try again", "error")
                    app.logger.warning("[pwd_reset]User does not exist : " + username)
                    sleep(random.uniform(4, 4.5)) # padded time to take into account hashing time for bcrypt
                    return redirect(url_for("resetPwd"))
            else :
                #unsafe username
                flash("Please try again", "error")
                app.logger.warning("[pwd_reset]Unsafe username provided : " + username)
                sleep(random.uniform(4, 4.5)) # padded time to take into account hashing time for bcrypt
                return redirect(url_for("resetPwd"))
    else:
        return render_template("reset_pwd.html")

if __name__ == "__main__":
    db.drop_all() # drops db when server restarts
    db.create_all()
    # context = ('cert.pem','key.pem') # if you use your own cert, uncomment
    context = 'adhoc' # only for testing. 
    app.run(ssl_context=context, debug=True)