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

        #decryption new variable here 

        self.current_user = {
            'email': user['email'],
            'password': user['password'],
            'address': user['address'],
            'dob': user['dob'],
            'disability': user['disability'],
            'salt': user['salt'],
            'display_name': user['displayName']
        }
