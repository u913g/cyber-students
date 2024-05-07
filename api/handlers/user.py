from tornado.web import authenticated
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['password'] = self.current_user['pwhashed']

        encrypted_address = self.current_user['address']
        ciphertext = encrypted_address
        ciphertext_bytes = bytes.fromhex(ciphertext)
        
        key = "theluckykeyisace"
        key_bytes = bytes(key, "utf-8")
        nonce_bytes = b'\x84\xf2\xc5]\x06\x1f\xc8Z\xb3\xe3\xc2\xd61\xf1~\xd4'

#encryptor and decryptor created
        aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                                mode=modes.CTR(nonce_bytes))
        aes_ctr_decryptor = aes_ctr_cipher.decryptor()

#decrypt ciphertext
        plaintext_bytes = aes_ctr_decryptor.update(ciphertext_bytes)
        plaintext = str(plaintext_bytes, "utf-8")

        self.response['address'] = self.current_user['plaintext']
        self.response['dob'] = self.current_user['dob']
        self.response['disability'] = self.current_user['disability']
        self.response['salt'] = self.current_user['saltH']
        self.response['displayName'] = self.current_user['display_name']
        
        self.write_json()

