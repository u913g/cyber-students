import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt

from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine

from .base import BaseHandler

class RegistrationHandler(BaseHandler):

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
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
            address = body['address']
            if not isinstance(address, str):
                raise Exception()
            dob = body['dob']
            if not isinstance(dob, str):
                raise Exception()           
            disability = body['disability']
            if not isinstance(disability, str):
                raise Exception()
            
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return
        
        if not address:
            self.send_error(400, message='The address is invalid!')
            return
        
        if not dob:
            self.send_error(400, message='The dob is invalid!')
            return
        
        if not disability:
            self.send_error(400, message='The disability is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return


#Step 1: generate the salt -  16 bytes (128 bits)
        salt = os.urandom(16)
#Step 2: configure the PBKDF
        kdf = Scrypt(salt=salt, length=32, n=2**14, r=8, p=1)
#Step3: password hash here
        password_bytes = bytes(password, "utf-8")
        hashed_password = kdf.derive(password_bytes)
        #cast hashed password into hex and save to pwhashed
        pwhashed = hashed_password.hex()
        #cast salt into hex for displaying and checking
        saltH = salt.hex()

       
        ### Inserts the user data (including email, hashed password,
        ### encrypted address, etc.) into the database.
        yield self.db.users.insert_one({
            'email': email,
            'password': pwhashed,
            'address': address,
            'dob': dob,
            'disability': disability,
            'salt': saltH,
            'displayName': display_name
        })
        
        self.set_status(200)
        self.response['email'] = email
        self.response['password'] = pwhashed #added here for testing purposes
        self.response['address'] = address
        self.response['dob'] = dob
        self.response['disability'] = disability
        self.response['salt'] = saltH # added it here for testing purposes
        self.response['displayName'] = display_name

        self.write_json()
