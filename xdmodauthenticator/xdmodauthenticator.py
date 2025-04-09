from jose import jwt
from jose.exceptions import ExpiredSignatureError
from jupyterhub.handlers import BaseHandler
from jupyterhub.auth import Authenticator
from jupyterhub.auth import LocalAuthenticator
from jupyterhub.utils import url_path_join
from tornado import gen, web
from traitlets import Unicode, Bool

class XDMoDLoginHandler(BaseHandler):

    def get(self):
        header_name = self.authenticator.header_name

        auth_cookie_content = self.get_cookie("XSRF-TOKEN", "")
        signing_certificate = self.authenticator.signing_certificate
        secret = self.authenticator.secret
        username_claim_field = self.authenticator.username_claim_field
        audience = self.authenticator.expected_audience

        cookie = self.get_cookie(self.authenticator.xdmod_cookie_name, None)
        if cookie:
            try:
                claims = ""
                if secret:
                    claims = self.verify_jwt_using_secret(cookie, secret, audience)
                elif signing_certificate:
                    claims = self.verify_jwt_with_claims(cookie, signing_certificate, audience)
            except ExpiredSignatureError:
                self.redirect(self.authenticator.authorization_endpoint)
        else:
            self.redirect(self.authenticator.authorization_endpoint)

        username = self.retrieve_username(claims, username_claim_field)
        user = self.user_from_username(username)
        self.set_login_cookie(user)

        _url = url_path_join(self.hub.server.base_url, 'home')
        next_url = self.get_argument('next', default=False)
        if next_url:
             _url = next_url

        self.redirect(_url)

    @staticmethod
    def verify_jwt_with_claims(token, signing_certificate, audience):
        with open(signing_certificate, 'r') as rsa_public_key_file:
            return jwt.decode(token, rsa_public_key_file.read(), audience=audience)

    @staticmethod
    def verify_jwt_using_secret(json_web_token, secret, audience):
        return jwt.decode(json_web_token, secret, algorithms=list(jwt.ALGORITHMS.SUPPORTED), audience=audience)

    @staticmethod
    def retrieve_username(claims, username_claim_field):
        username = claims[username_claim_field]
        if "@" in username:
            return username.split("@")[0]
        else:
            return username


class XDMoDAuthenticator(Authenticator):
    """
    Authenticate using an instance of XDMoD.
    """
    signing_certificate = Unicode(
        config=True,
        help="""
        The public certificate of the private key used to sign the incoming JSON Web Tokens.

        Should be a path to an X509 PEM format certificate filesystem.
        """
    )

    username_claim_field = Unicode(
        default_value='sub',
        config=True,
        help=""" The claim field that contains the username. """
    )

    expected_audience = Unicode(
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    header_name = Unicode(
        default_value='Authorization',
        config=True,
        help="""HTTP header to inspect for the authenticated JSON Web Token."""
    )

    secret = Unicode(
        config=True,
        help="""Shared secret key for siging JWT token.  If defined, it overrides any setting for signing_certificate""")

    authorization_endpoint = Unicode(
        default_value='/rest/users/current/api/jsonwebtoken',
        config=True,
        help=""" XDMoD REST endpoint to authorize user """
    )

    xdmod_cookie_name = Unicode(
        default_value='xdmod_jupyterhub_token',
        config=True,
        help=""" Name of cookie set by XDMoD """
    )

    def get_handlers(self, app):
        return [
            (r'/login', XDMoDLoginHandler),
        ]

    @gen.coroutine
    def authenticate(self, *args):
        raise NotImplementedError()


class XDMoDAuthenticator(XDMoDAuthenticator, LocalAuthenticator):
    """
    A version of the Authenticator that mixes in local system user creation
    """
    pass
