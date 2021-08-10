"""htpasswd authentication module"""

from passlib.apache import HtpasswdFile
from werkzeug.http import parse_authorization_header

from . import PreAuthorizedActionAuthenticator
from .identity import DefaultIdentity, Permission


class HtpasswdAuthenticator(PreAuthorizedActionAuthenticator):

    def __init__(self, filename):
        self.filename = filename

    def __call__(self, request):
        # Try getting cleartext username + password from header
        header = request.headers.get('Authorization')
        if not header:
            return
        if header.split(' ')[0] != 'Basic':
            return

        # Extract username + password
        parsed_header = parse_authorization_header(header)

        # Validate against db
        db = HtpasswdFile(self.filename)
        if not db.check_password(parsed_header.username, parsed_header.password):
            return

        # Create user and grant permissions
        user = DefaultIdentity(parsed_header.username)
        user.allow(permissions=Permission.all())
        return user


def factory(**options):
    filename = options.get('filename', 'htpasswd')
    return HtpasswdAuthenticator(filename)
