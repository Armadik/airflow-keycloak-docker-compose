import os
import logging

import jwt
import requests
from base64 import b64decode
from cryptography.hazmat.primitives import serialization
from flask_appbuilder import expose
from flask_appbuilder.security.manager import AUTH_OAUTH
from flask_appbuilder.security.views import AuthOAuthView

from airflow.www.security import AirflowSecurityManager

basedir = os.path.abspath(os.path.dirname(__file__))
log = logging.getLogger(__name__)

os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'

APP_THEME = "darkly.css"
AUTH_TYPE = AUTH_OAUTH
AUTH_USER_REGISTRATION = True
AUTH_USER_REGISTRATION_ROLE = "Public"
AUTH_ROLES_SYNC_AT_LOGIN = True

AUTH_ROLES_MAPPING = {
    "airflow_admins": ["Admin"],
    "airflow_users": ["User"],
    "airflow_viewers": ["Viewer"],
}
OAUTH_PROVIDERS = [{
    'name': 'keycloak',
    'icon': 'fa-key',
    'token_key': 'access_token',
    'remote_app': {
        'client_id': 'airflow',
        'client_secret': 'EIhxJQW2U4DIOEMHHMtKyWVBrpbj20DK',
        'request_token_url': None,
        'api_base_url': 'http://keycloak:8080/realms/master/protocol/openid-connect',
        'client_kwargs': {
            'scope': 'openid email profile'
        },
        'access_token_url': 'http://keycloak:8080/realms/master/protocol/openid-connect/token',
        'authorize_url': 'http://localhost:8080/realms/master/protocol/openid-connect/auth',
        'jwks_uri': 'http://keycloak:8080/realms/master/protocol/openid-connect/certs',
    }
}]


class CustomAuthRemoteUserView(AuthOAuthView):
    @expose("/logout/")
    def logout(self):
        """Delete access token before logging out."""
        return super().logout()


class CustomSecurityManager(AirflowSecurityManager):
    authoauthview = CustomAuthRemoteUserView

    def oauth_user_info(self, provider, response):
        if provider == 'keycloak':
            OIDC_ISSUER = 'http://keycloak:8080/realms/master'
            req = requests.get(OIDC_ISSUER)
            key_der_base64 = req.json()["public_key"]
            key_der = b64decode(key_der_base64.encode())
            public_key = serialization.load_der_public_key(key_der)

            token = response["access_token"]
            me = jwt.decode(token, public_key, algorithms="RS256", verify=False, audience='account')
            groups = me["resource_access"]["airflow"]["roles"]  # unsafe
            if len(groups) < 1:
                groups = ["airflow_public"]
            else:
                groups = [str for str in groups if "airflow" in str]

            userinfo = {
                "username": me.get("preferred_username"),
                "email": me.get("email"),
                "first_name": me.get("given_name"),
                "last_name": me.get("family_name"),
                "role_keys": groups,
            }
            log.info("user info: {0}".format(userinfo))
            return userinfo
        else:
            return {}


SECURITY_MANAGER_CLASS = CustomSecurityManager
