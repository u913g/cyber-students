from tornado.web import authenticated

from .auth import AuthHandler

class UserHandler(AuthHandler):

    @authenticated
    def get(self):
        self.set_status(200)
        self.response['email'] = self.current_user['email']
        self.response['password'] = self.current_user['pwhashed']
        self.response['address'] = self.current_user['address']
        self.response['dob'] = self.current_user['dob']
        self.response['disability'] = self.current_user['disability']
        self.response['salt'] = self.current_user['saltH']
        self.response['displayName'] = self.current_user['display_name']
        self.write_json()

