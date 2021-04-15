## Setup
1. Activate Virtual Environment
- `source env/bin/activate`

2. Set up `.env` environment variables
- run `cp .env_sample .env` and edit the environment variables in `.env`.

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
- [ ] Prevention of timing attacks
- [ ] Logging
- [x] CSRF prevention
    - implemented with `flask_wtf.csrf`
- [ ] Multi factor authentication
- [ ] Password reset / forget password mechanism
- [ ] Account lockout
- [ ] Cookie
- [x] HTTPS
    - self-signed certificate
- [x] Known password check
    - checked against Top 10000 password from [SecList](https://github.com/danielmiessler/SecLists/blob/master/Passwords/Common-Credentials/10k-most-common.txt)
