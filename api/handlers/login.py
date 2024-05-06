import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
#from registration.py import hPassword

from datetime import datetime, timedelta
from time import mktime
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from uuid import uuid4

from .base import BaseHandler

class LoginHandler(BaseHandler):

    @coroutine
    def generate_token(self, email):
        token_uuid = uuid4().hex
        expires_in = datetime.now() + timedelta(hours=2)
        expires_in = mktime(expires_in.utctimetuple())

        token = {
            'token': token_uuid,
            'expiresIn': expires_in,
        }

        yield self.db.users.update_one({
            'email': email
        }, {
            '$set': token
        })

        return token

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
        except:
            self.send_error(400, message='You must provide an email address and password!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        ##Searches for a user with an email address in the db, 
        ##The yield keyword is used to pass a value back
        ##
        ##The find_one() method of self.db.users in the db is being
        ##called with two arguments: a dictionary that specifies the search criteria
        ##(the email address to search for), and another that specifies which
        ##fields to include in the result
        ##(the 'password' which is a hash and, and the 'salt' field which is a hex).
        user = yield self.db.users.find_one({
          'email': email
        }, {
          'password': 1,#this searches for password stored in db which is hashed password
          'salt': 1
        })

        if user is None:
            self.send_error(403, message='The email address and password are invalid!')
            return
        #to distinguish between the login password and the db hashed password passwordH is used
        passwordH = user['password']
        salt = user['salt']
        saltB = bytes.fromhex(salt)
#       saltS = bytes(salt, "utf-8")

#rehash here
        kdf = Scrypt(saltB, length=32, n=2**14, r=8, p=1)
        #Step3: password rehash
        #password here is the login password
        password_bytes = bytes(password, "utf-8")
        hashed_password = kdf.derive(password_bytes)

        
#       if user['password'] != hashed_password.hex():
        if passwordH != hashed_password.hex():
            self.send_error(403, message='The email address or password is invalid!')
            return

        token = yield self.generate_token(email)

        self.set_status(200)
        self.response['token'] = token['token']
        self.response['expiresIn'] = token['expiresIn']

        self.write_json()
