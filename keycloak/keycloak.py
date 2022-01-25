import requests
import datetime
from storage.settings import KEYCLOAK_CLIENT_SECRET


class Keycloak:
    token = ''

    def get_token(self):
        url = 'http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/userinfo'
        response = requests.request("GET", url, headers={'Authorization': "Bearer " + self.token})
        if response.status_code == 200:
            return self.token
        payload = {
            "client_id": "lox",
            "client_secret": KEYCLOAK_CLIENT_SECRET,
            "grant_type": "client_credentials",
            "Content-Type": "application/x-www-form-urlencoded",
        }
        url = "http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/token"
        response = requests.post(url, data=payload)
        response = response.json()
        self.token = response['access_token']
        return self.token

    # this function has to be a decorator
    # def check_token(self, response, function, *args):
    #     if response.status_code == 200:
    #         return True
    #     if response.status_code == 401:
    #         self.get_token()
    #         function(*args)
    #     return False

    def get_user_by_userid(self, userid):
        url = 'http://127.0.0.1:8080/auth/admin/realms/demo/users/'
        response = requests.request("GET", url + userid, headers={'Authorization': "Bearer " + self.token}, params={})
        if response.status_code == 200:
            response = response.json()
            users = []
            user = {
                'username': response['username'],
                'id': response['id'],
                'enabled': response['enabled'],
                'roles': self.get_user_roles(response['id'])
            }
            users.append(user)
            return users
        elif response.status_code == 401:
            self.get_token()
            return self.get_user_by_userid(userid)
        return 'user not found'

    def get_users_by_username(self, username):
        url = 'http://127.0.0.1:8080/auth/admin/realms/demo/users/'
        response = requests.request("GET", url, headers={'Authorization': "Bearer " + self.token},
                                    params={'username': username})
        if response.status_code == 200:
            response = response.json()
            users = []
            for user in response:
                u = {
                    'username': user['username'],
                    'id': user['id'],
                    'enabled': user['enabled'],
                    'roles': self.get_user_roles(user['id'])
                }
                users.append(u)
            return users
        elif response.status_code == 401:
            self.get_token()
            return self.get_users_by_username(username)
        return 'user not found'

    def get_user_roles(self, userid):
        url = 'http://127.0.0.1:8080/auth/admin/realms/demo/users/'
        response = requests.request("GET", url + userid + '/role-mappings/',
                                    headers={'Authorization': "Bearer " + self.token}, params={})
        response = response.json()
        roles = []
        for result in response:
            for res in response[result]:
                if type(res) == dict:
                    roles.append(res['name'])
                else:
                    for q in response[result][res]['mappings']:
                        roles.append(q['name'])
        return roles

    def get_user_events(self, date_from, date_to, user_id, search_types):
        http = 'http://127.0.0.1:8080/auth/admin/realms/demo/events/'
        response = requests.request("GET", http, headers={'Authorization': "Bearer " + self.token},
                                    params={'max': 1000, 'dateFrom': date_from, 'dateTo': date_to,
                                            'user': user_id, 'type': search_types})
        response = response.json()
        types = []
        for res in response:
            date = datetime.datetime.fromtimestamp(res['time'] / 1000.0) + datetime.timedelta(hours=3)
            date = date.strftime('%Y-%m-%d %H:%M:%S')
            res['time'] = date
            del res['details']
            types.append(res)
        return types
