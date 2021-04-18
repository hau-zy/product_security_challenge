from project import server

"""
md5 hash function check
"""
def test_md5_hash_gen_correct(tmpdir):
    p = tmpdir.mkdir("sub").join("test.txt")
    p.write("content")
    hash = server.md5(p)
    assert hash == "9a0364b9e99bb480dd25e1f0284c8555", "should be true"

def test_md5_hash_gen_incorrect(tmpdir):
    p = tmpdir.mkdir("sub").join("test.txt")
    p.write("content")
    hash = server.md5(p)
    assert hash != "not_valid_hash", "should be true"

"""
Username Safety Check
"""
def test_safe_username1():
    res = server.isUsernameSafe('userName00-')
    assert res==True, "should be true"

def test_unsafe_username1():
    res = server.isUsernameSafe('username`')
    assert res==False, "should be false"

def test_unsafe_username2():
    res = server.isUsernameSafe('username`')
    assert res==False, "should be false"

def test_unsafe_username3():
    res = server.isUsernameSafe('<username')
    assert res==False, "should be false"

def test_unsafe_username4():
    res = server.isUsernameSafe('username>')
    assert res==False, "should be false"

"""
Password Check
"""
def test_common_password():
    res =  server.isCommonPwd('password')
    assert res==True, "should be true"

def test_uncommon_password():
    res = server.isCommonPwd('a^&=?Q4w&5*qKS@h')
    assert res == False, "should be true"

def test_overall_password_check_ok1():
    res =  server.pwdCheck('a^&=?Q4w&5*qKS@h')
    assert res['password_ok'] == True 

def test_overall_password_check_ok2():
    res =  server.pwdCheck('ZendeskSecTest2021@!')
    assert res['password_ok'] == True 

def test_overall_common_password():
    res =  server.pwdCheck('password')
    assert (res['password_ok'] == False and res['common_pwd'] == True)  == True

def test_overall_short_password() :
    res =  server.pwdCheck('a^&=?Q4')
    assert (res['password_ok'] == False and res['length_error'] == True) == True

def test_overall_no_digit_password() :
    res =  server.pwdCheck('ZendeskSecTest!')
    assert (res['password_ok'] == False and res['digit_error'] == True) == True

def test_overall_no_uppercase_password() :
    res =  server.pwdCheck('zendesksectest2021!')
    assert (res['password_ok'] == False and res['uppercase_error'] == True)== True

def test_overall_no_lowercase_password() :
    res =  server.pwdCheck('ZENDESKSECTEST2021!')
    assert (res['password_ok'] == False and res['lowercase_error'] == True) == True

def test_overall_no_symbol_password() :
    res =  server.pwdCheck('ZendeskSecTest2021')
    assert (res['password_ok'] == False and res['symbol_error'] == True) == True

"""
JWT Encode and Decode
- does not test token expiry
- does not test base64decode and change sub 
"""
def test_valid_jwt_encode_decode():
    token = server.encode_auth_token(99)
    decoded_token = server.decode_auth_token(token)
    assert decoded_token == 99

def test_invalid_jwt_encode_decode():
    token = server.encode_auth_token(99)
    new = list(token)
    if new[-3] != 'Z' :
        new[-3] = 'Z'
    else :
        new[-3] = 'D'
    invalid_token = ''.join(new)
    decoded_token = server.decode_auth_token(invalid_token)
    assert decoded_token == 'Invalid token. Please log in again.'