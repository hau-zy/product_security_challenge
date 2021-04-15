## Setup
1. Activate Virtual Environment
`source env/bin/activate`
2. Generate SSL certs (you need to have openssl installed)
`openssl req -x509 -newkey rsa:4096 -nodes -out cert.pem -keyout key.pem -days 365`
3. Run Flask Server
`python3 server.py`
4. Web App
From browser visit `https://localhost:5000`. You will need to allow self-signed certificate.
    
## Functionalities
- [ ] Input sanitization and validation
- [ ] Password hashed
- [ ] Prevention of timing attacks
- [ ] Logging
- [x] CSRF prevention
- [ ] Multi factor authentication
- [ ] Password reset / forget password mechanism
- [ ] Account lockout
- [ ] Cookie
- [x] HTTPS
- [x] Known password check
