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
    - username input validation to prevent injection
- [x] Password hashed
    - bcrypt with random salt for each user
- [X] Prevention of timing attacks
    - Random sleep time between 0-1.5s before login result is returned back to user
- [X] Logging
- [x] CSRF prevention
    - implemented with `flask_wtf.csrf`
- [ ] Multi factor authentication
- [ ] Password reset / forget password mechanism
- [X] Account lockout
    - account is locked out for 5min after 5 wrong password attempts
- [X] Cookie
    - JSON Web Tokens stored as `auth_cookie`
- [x] HTTPS
    - self-signed certificate
- [x] Known password check
    - checked against Top 10000 password from [SecList](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt)
