from django.contrib.auth.backends import RemoteUserBackend
from django.contrib.auth.models import User
import requests


class KeycloakBackend(RemoteUserBackend):
    def authenticate(self, request):
        http = 'http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/userinfo'
        response = requests.request("GET", http, headers={'Authorization': "Bearer " + request.content_params['token']})
        if response.status_code == 200:
            try:
                user = User.objects.get(id=request.content_params['user_id'])
            except User.DoesNotExist:
                return None
            return user
        return None
