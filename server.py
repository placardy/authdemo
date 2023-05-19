import base64
import hmac
import hashlib
import json
from typing import Optional

from fastapi import FastAPI, Form, Cookie, Body
from fastapi.responses import Response

SECRET_KEY = "1795e2a69fafe64d6182ed0dfa9b05b5b27fe1ce8ea3532f675c0f6ac5841620"
PASSWORD_SALT = "1bee10db70917fc378e89fda80cbba36d0b3a4ecdebff5bbc21a657688a0a985"

app = FastAPI()

def sign_data(data: str) -> str:
    """Returns signed data"""
    return hmac.new(
        SECRET_KEY.encode(),
        msg=data.encode(),
        digestmod=hashlib.sha256
    ).hexdigest().upper()

def get_username_for_signed_string(username_signed: str) -> Optional[str]:
    """The function accepts signed data and returns the username if the signature is valid"""
    username_base64, sign = username_signed.split('.')
    username = base64.b64decode(username_base64.encode()).decode()
    valid_sign = sign_data(username)
    print('-----------------------')
    print(username_base64, sign)
    print('username is', username)
    print(valid_sign)
    print('----------------------')
    if hmac.compare_digest(valid_sign, sign):
        return username

def verify_password(username: str, password: str) -> bool:
    """The function hashes the password and compares it with the stored password"""
    password_hash = hashlib.sha256((password + PASSWORD_SALT).encode()).hexdigest().lower()
    stored_password_hash = users[username]['password'].lower()
    return  password_hash == stored_password_hash

users = {
    "eugene@user.com" : {
        "name" : "Eugene",
        "password" : "b294fd475a50ab019021aeb46cc9498c664515bec65823b216d28319e15f08b5",
        "balance" : 100_000
    },
    "petr@user.com" : {
        "name" : "Petr",
        "password" : "a81e31683e9b5bc54df76b8e34abcbf974c04cabeec22b8c0e755cee9fdc22d4",
        "balance" : 90_000
    }
}

@app.get("/")
def index_page(username: Optional[str] = Cookie(default=None)):
    with open('templates/login.html', 'r') as f:
        login_page = f.read()
    if not username:
        return Response(login_page, media_type="text/html")
    valid_username = get_username_for_signed_string(username)
    if not valid_username:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key='username')
        return response
    try:
        user = users[valid_username]
    except KeyError:
        response = Response(login_page, media_type="text/html")
        response.delete_cookie(key="username")
        return response
    return Response(
        f"Привет! {users[valid_username]['name']}!<br />"
        f"Баланс: {users[valid_username]['balance']}<br />"
        f"After reload",
        media_type="text/html")

# def process_login_page(username: str = Form(...), password: str = Form(...)):
@app.post("/login")
def process_login_page(data: dict = Body(...)):
    username = data["username"]
    password = data["password"]
    user = users.get(username)
    if not user or not verify_password(username, password):
        return Response(
            json.dumps({
                "success": False,
                "message": "Неверный логин или пароль"
            }), 
            media_type='application/json')

    response = Response(
        json.dumps({
            "success": True,
            "message": f"Привет: {user['name']}!<br />Баланс: {user['balance']}" 
        }),
        media_type='application/json')
    username_signed = base64.b64encode(username.encode()).decode() + "." + sign_data(username)
    response.set_cookie(key="username", value=username_signed)
    return response