import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

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
########## Salt ######################

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

########### Encryption ###############
        key = "theluckykeyisace"
    
        key_bytes = bytes(key, "utf-8")
        nonce_bytes = b'\x84\xf2\xc5]\x06\x1f\xc8Z\xb3\xe3\xc2\xd61\xf1~\xd4'

    
#aes in counter mode
#nonce needed here in order to initialise it.
#encryptor and decryptor created
        aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                                mode=modes.CTR(nonce_bytes))
        aes_ctr_encryptor = aes_ctr_cipher.encryptor()

#user_address = user_address_in
    #set plaintext
        plaintext = address
        plaintext_bytes = bytes(plaintext, "utf-8")

    #encrypt plaintext
        ciphertext_bytes = aes_ctr_encryptor.update(plaintext_bytes)
        ciphertext = ciphertext_bytes.hex()

       
        ### Inserts the user data (including email, hashed password,
        ### encrypted address, etc.) into the database.
        yield self.db.users.insert_one({
            'email': email,
            'password': pwhashed,
            'address': ciphertext,
            'dob': dob,
            'disability': disability,
            'salt': saltH,
            'displayName': display_name
        })
        
        self.set_status(200)
        self.response['email'] = email
        self.response['password'] = pwhashed #added here for testing purposes
        self.response['address'] = ciphertext
        self.response['dob'] = dob
        self.response['disability'] = disability
        self.response['salt'] = saltH # added it here for testing purposes
        self.response['displayName'] = display_name

        self.write_json()
