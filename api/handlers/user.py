from tornado.web import authenticated
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['password'] = self.current_user['pwhashed']

#address decryption
        encrypted_address = self.current_user['address']
        decrypted_address = self.decrypt_details(encrypted_address)
#display_name decryption
        encrypted_display_name = self.current_user['display_name']
        decrypted_display_name = self.decrypt_details(encrypted_display_name)
#dob decryption
        encrypted_dob = self.current_user['dob']
        decrypted_dob = self.decrypt_details(encrypted_dob)
#disability decryption
        encrypted_disability = self.current_user['disability']
        decrypted_disability = self.decrypt_details(encrypted_disability)
        
        self.response['address'] = decrypted_address
        self.response['dob'] = decrypted_dob
        self.response['disability'] = decrypted_disability
        self.response['salt'] = self.current_user['saltH']
        self.response['displayName'] = decrypted_display_name
        
        self.write_json()

    def decrypt_details(self, encrypted_details):#self, might need to go here
        key = "theluckykeyisace"
        key_bytes = bytes(key, "utf-8")
        nonce_bytes = b'\x84\xf2\xc5]\x06\x1f\xc8Z\xb3\xe3\xc2\xd61\xf1~\xd4'

        ciphertext_bytes = bytes.fromhex(encrypted_details)
        aes_ctr_cipher = Cipher(algorithms.AES(key_bytes),
                                mode=modes.CTR(nonce_bytes))
        aes_ctr_decryptor = aes_ctr_cipher.decryptor()

        decrypted_details_bytes = aes_ctr_decryptor.update(ciphertext_bytes) + aes_ctr_decryptor.finalize()
        decrypted_details = decrypted_details_bytes.decode("utf-8")
        
        return decrypted_details
        
