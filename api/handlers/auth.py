import os
from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from datetime import datetime
from time import mktime
from tornado.gen import coroutine

from .base import BaseHandler

class AuthHandler(BaseHandler):

    @coroutine
    def prepare(self):
        super(AuthHandler, self).prepare()

        if self.request.method == 'OPTIONS':
            return

        try:
            token = self.request.headers.get('X-Token')
            if not token:
              raise Exception()
        except:
            self.current_user = None
            self.send_error(400, message='You must provide a token!')
            return

        user = yield self.db.users.find_one({
            'token': token
        }, {
            'email': 1,
            'password': 1,
            'address': 1,
            'dob': 1,
            'disability': 1,
            'salt': 1,
            'displayName': 1,
            'expiresIn': 1
        })

        if user is None:
            self.current_user = None
            self.send_error(403, message='Your token is invalid!')
            return

        current_time = mktime(datetime.now().utctimetuple())
        if current_time > user['expiresIn']:
            self.current_user = None
            self.send_error(403, message='Your token has expired!')
            return

        # Decrypt details
        decrypted_address = self.decrypt_details(user['address'])
        decrypted_dob = self.decrypt_details(user['dob'])
        decrypted_disability = self.decrypt_details(user['disability'])
        decrypted_display_name = self.decrypt_details(user['displayName'])
        
#decryption new variables
        #nonce should never be used only once but is hardcoded here for testing
        #in the final version, it will be incrementing by 1 each time used.
        nonce_bytes = b'\x84\xf2\xc5]\x06\x1f\xc8Z\xb3\xe3\xc2\xd61\xf1~\xd4'
        key = "theluckykeyisace"
        key_bytes = bytes(key, "utf-8")
        #aes in counter mode
        #nonce needed here in order to initialise it.
        #encryptor and decryptor created
        aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                        mode=modes.CTR(nonce_bytes))
        aes_ctr_decryptor = aes_ctr_cipher.decryptor()

        #decrypt address
        address_bytesb = bytes.fromhex(address)
        dec_address_bytes_2 = aes_ctr_decryptor.update(address_bytesb)
        decrypted_address = str(dec_address_bytes_2, "utf-8")

        #decrypt dob
        dob_bytesb = bytes.fromhex(dob)
        dec_dob_bytes_2 = aes_ctr_decryptor.update(dob_bytesb)
        decrypted_dob = str(dec_dob_bytes_2, "utf-8")

        #decrypt disability
        disability_bytesb = bytes.fromhex(disability)
        dec_disability_bytes_2 = aes_ctr_decryptor.update(disability_bytesb)
        decrypted_disability = str(dec_disability_bytes_2, "utf-8")

        #decrypt display name
        dname_bytesb = bytes.fromhex(display_name)
        dec_dname_bytes_2 = aes_ctr_decryptor.update(dname_bytesb)
        decrypted_display_name = str(dec_dname_bytes_2, "utf-8")
        
                
        self.response['address'] = decrypted_address
        self.response['dob'] = decrypted_dob
        self.response['disability'] = decrypted_disability
        self.response['salt'] = self.current_user['saltH']
        self.response['displayName'] = decrypted_display_name
        
        self.write_json()

        decrypted_address = self.decrypt_details(user['address'])
        decrypted_dob = self.decrypt_details(user['dob'])
        decrypted_disability = self.decrypt_details(user['disability'])
        decrypted_display_name = self.decrypt_details(user['displayName'])

        
    def decrypt_details(self, encrypted_details):
        key = "theluckykeyisace"
        key_bytes = bytesbytes(key, "utf-8")
        nonce_bytes = b'\x84\xf2\xc5]\x06\x1f\xc8Z\xb3\xe3\xc2\xd61\xf1~\xd4'

        ciphertext_bytes = bytes.fromhex(encrypted_details)
        aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                                mode=modes.CTR(nonce_bytes))
        aes_ctr_decryptor = aes_ctr_cipher.decryptor()

        decrypted_details_bytes = aes_ctr_decryptor.update(ciphertext_bytes) + aes_ctr_decryptor.finalize()
        decrypted_details = decrypted_details_bytes.decode('utf-8')
        
        return decrypted_details


        self.current_user = {
            'email': user['email'],
            'password': user['password'],
            'address': decrypted_address,
            'dob': decrypted_dob,
            'disability': decrypted_disability,
            'salt': user['salt'],
            'display_name': decrypted_display_name
        }
