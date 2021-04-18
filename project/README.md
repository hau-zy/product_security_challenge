## Setup
1. Activate Virtual Environment
- `source env/bin/activate`

2. Set up `.env` environment variables
- run `cp .env_sample .env` and edit the environment variables in `.env` file.

3. Generate SSL certs (you need to have openssl installed)
- `openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365`

4. Run Flask Server
- `python3 server.py`

5. Web App
- From browser visit `https://localhost:5000`. You will need to allow self-signed certificate.
    
## Functionalities
- [x] Input sanitization and validation
    - Username input validation to prevent injection.
- [x] Password hashed
    - Passwords are hashed using bcrypt with random salt for each user. Unique salt for each user as well as the use of cost factor would increase the effort for a malicious actor to perform offline dictionary attack.
- [X] Prevention of timing attacks
    - Random sleep time added before login result is returned back to user. Timing for both correct and incorrect login takes roughly the same time to prevent malicious actors from guessing password with timing attacks.
- [X] Logging
    - Logging of login attempts (successful and unsuccessful) is implemented with `logging` library.
- [x] CSRF prevention
    - Implemented with `flask_wtf.csrf`. 
- [ ] Multi-factor authentication
- [X] Password reset / forget password mechanism
    - Password reset functionality is implemented with user providing existing password as authentication of user. However, for Forget Password, multi-factor authentication is required to verify that the password change is initated by the user.
- [X] Account lockout
    - Account is locked out for 5min after 5 wrong password attempts.
- [X] Cookie
    - JSON Web Tokens (JWT) stored as `auth` cookie. Prevents tampering with token signing. Replay attack can also be mitigated by setting expiry.
- [x] HTTPS
    - Self-signed certificate is used.
- [x] Known password check
    - Passwords are checked against Top 10000 password from [SecList](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt) before they are accepted as account password.
