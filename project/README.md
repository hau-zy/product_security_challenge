## Setup
0. Clone the Repository
    - run `git clone https://github.com/hau-zy/product_security_challenge.git`

1. Activate Virtual Environment
    - change directory to project folder `cd project`
    - run `source env/bin/activate`

2. Set up `.env` environment variables
    - run `cp .env_sample .env` and edit the environment variables in `.env` file.

3. Generate SSL certs (you need to have openssl installed)
    - run `openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365`

4. Run Flask Server from Command Line
    - run `python3 server.py`

5. Web App
    - From browser visit `https://localhost:5000`. You will need to allow self-signed certificate.
    - The database is empty and you would be required to sign up for an account first!

6. Generating Binary
    - run `pyinstaller -F --add-data "static:static" --add-data ".env:." --add-data "templates:templates" --add-data "10k-most-common.txt:." server.py`
    - binary file `server` would be in the `dist` folder

## Using Provided Binary
1. Run Binary `server.exe`

2. Web App
    - From browser visit `https://localhost:5000`. You will need to allow self-signed certificate.
    - The database is empty and you would be required to sign up for an account first!

## Functionalities
- [x] Input sanitization and validation
    - Username input validation to prevent injection.
    - Password Complexity is checked against NIST Password Guidelines:
        1. Password length of more than 8 characters and less than 64 characters
        2. Includes:
            - at least 1 Uppercase Alphabet
            - at least 1 Lowercase Alphabet
            - at least 1 Digit
            - at least 1 Special Character
- [x] Password hashed
    - Passwords are hashed using bcrypt with random salt for each user. Unique salt for each user as well as the use of cost factor would increase the effort for a malicious actor to perform offline dictionary attack.
- [X] Prevention of timing attacks
    - Random sleep time added before login result is returned back to user. Timing for both correct and incorrect login takes roughly the same time to prevent malicious actors from guessing password with timing attacks.
- [X] Logging
    - Logging of login attempts (successful and unsuccessful) is implemented with `logging` library.
- [x] CSRF prevention
    - Implemented with `flask_wtf.csrf`. 
- [X] Multi-factor authentication
    - Two-factor authentication is implemented by using a Time-based One Time Password [(TOTP)](https://en.wikipedia.org/wiki/Time-based_One-Time_Password), with the token being provided using Google Authenticator (or any free TOTP service). Acknowledgment : Referencing [Miguel Grinber's blog](https://blog.miguelgrinberg.com/post/two-factor-authentication-with-flask)
    - An improvement would be to provide user the option to re-generate new OTP secret (the seed for OTP generation).
- [X] Password reset / forget password mechanism
    - Password reset functionality is implemented 
        - Forget Password: Password can be resetted with user providing OTP, using a two-factor authentication to prevent as a way of verifying that the User initated the password change. (It would be better if there is a notification to user, informing them about such change request.)
        - Reset Password From Dashboard: The user has to be logged in (together with 2FA in the process) to access reset password page. Old password has to be provided.
- [X] Account lockout
    - Account is locked out for 5min after 5 wrong password attempts.
- [X] Cookie
    - JSON Web Tokens (JWT) stored as `auth` cookie. Prevents tampering with token signing. Replay attack can also be mitigated by setting expiry.
    - JWT is revoked after a user logs out of a session.
    - Improvement (TODO) : implement auth and refresh token system
- [x] HTTPS
    - Self-signed certificate is used. 
    - Added option to use `ssl_context=adhoc`. Not recommended.
- [x] Known password check
    - Passwords are checked against Top 10000 password from [SecList](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt) before they are accepted as account password.

## Test
- Running test
    - run `pytest`
- Additional Note:
    - Test coverage is not complete
