from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth.models import User
from django.views import View
from main.models import KeycloakUser
from requests_oauthlib import OAuth2Session
from main.models import TypeFilter
import requests, datetime, ast
import os
from django.contrib.auth import authenticate, login
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


class Keycloak:
    def __init__(self):
        pass


def get_keycloak_sat():
    payload = {
        "client_id": "lox",
        "client_secret": "gBSc7w7Iaen3IU2CvBS50jkSQRUDdLIa",
        "grant_type": "client_credentials",
        "Content-Type": "application/x-www-form-urlencoded",
    }
    http = "http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/token"
    token = requests.post(http, data=payload)
    token = token.json()

    return token['access_token']


def get_keycloak_user(token, name_type, name):
    http = 'http://127.0.0.1:8080/auth/admin/realms/demo/users/'
    user = {}
    # username = 0, userid = 1
    if name_type == '0':
        response = requests.request("GET", http, headers={'Authorization': "Bearer " + token, },
                                    params={'username': name})
        response = response.json()
        if len(response) > 0:
            users = []
            for user in response:
                u = {
                    'username': user['username'],
                    'id': user['id'],
                    'enabled': user['enabled'],
                    'roles': get_user_roles(token, user['id'])
                }
                users.append(u)
            return users
    elif name_type == '1':
        response = requests.request("GET", http + name, headers={'Authorization': "Bearer " + token, },
                                    params={})
        response = response.json()
        if len(response) > 1:
            user = []
            u = {
                'username': response['username'],
                'id': response['id'],
                'enabled': response['enabled'],
                'roles': get_user_roles(token, response['id'])
            }
            user.append(u)
            return user
    return user


def get_user_events(token, date_from, date_to, user_id, types):
    http = 'http://127.0.0.1:8080/auth/admin/realms/demo/events/'
    response = requests.request("GET", http, headers={'Authorization': "Bearer " + token, },
                                params={'max': 1000, 'dateFrom': date_from, 'dateTo': date_to,
                                        'user': user_id, 'type': types})
    response = response.json()
    result = []
    for res in response:
        date = datetime.datetime.fromtimestamp(res['time'] / 1000.0) + datetime.timedelta(hours=3)
        date = date.strftime('%Y-%m-%d %H:%M:%S')
        res['time'] = date
        del res['details']
        result.append(res)
    return result


def get_user_roles(token, user_id):
    http = 'http://127.0.0.1:8080/auth/admin/realms/demo/users/'
    response = requests.request("GET", http + user_id + '/role-mappings/', headers={'Authorization': "Bearer " + token,
                                                                                    }, params={})
    response = response.json()
    results = []
    for result in response:
        for res in response[result]:
            if type(res) == dict:
                results.append(res['name'])
            else:
                for q in response[result][res]['mappings']:
                    results.append(q['name'])
    return results


def index_page(request):
    context = {
        'pagename': 'Главная',
    }
    return render(request, 'pages/index.html', context)


def auth(request):
    return render(request, '')


class EventsView(View):
    def __init__(self, *args, **kwargs):
        self.context = {
            'pagename': 'Главная',
            'dateFrom': datetime.date.today().strftime("%Y-%m-%d"),
            'dateTo': (datetime.date.today() + datetime.timedelta(days=1)).strftime("%Y-%m-%d"),
            'radio_username': 'checked',
        }
        super().__init__(*args, **kwargs)

    def get_extra_context(self, form):
        types = form.getlist('types-select')
        if types:
            for typ in types:
                self.context[typ] = 'selected'
        if form['for_name'] == '0':
            self.context['radio_username'] = 'checked'
        elif form['for_name'] == '1':
            self.context['radio_userId'] = 'checked'
        self.context['dateFrom'] = form['dateFrom']
        self.context['dateTo'] = form['dateTo']

    def get_users(self, form):
        token = get_keycloak_sat()
        selected_users = form.getlist('users')
        if selected_users:
            users = []
            for user in selected_users:
                users.append(ast.literal_eval(user))
        else:
            users = get_keycloak_user(token, form['for_name'], form['name'])
        return users

    def get_events(self, form, users):
        types = form.getlist('types-select')
        token = get_keycloak_sat()
        if users:
            self.context['events'] = []
            for user in users:
                self.context['events'].append(get_user_events(token, form['dateFrom'], form['dateTo'], user['id'], types))
            self.context['users'] = users
            self.context['user_found'] = True
        else:
            self.context['user_found'] = False

    @method_decorator(login_required)
    def get(self, request):
        return render(request, 'pages/events/events.html', self.context)

    @method_decorator(login_required)
    def post(self, request):
        form = request.POST
        print(form)
        users = self.get_users(form)
        self.get_events(form, users)
        self.get_extra_context(form)
        print(self.context)
        return render(request, 'pages/events/events.html', self.context)


# keycloak oidc login
def oidc_login(request):
    client_id = 'lox'
    redirect_uri = 'http://127.0.0.1:8000/callback'
    scope = 'openid email profile'
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    authorization_url, state = oauth.authorization_url(
        'http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/auth')
    return redirect(authorization_url)


def callback(request):
    client_id = 'lox'
    client_secret = 'gBSc7w7Iaen3IU2CvBS50jkSQRUDdLIa'
    response = 'http://127.0.0.1:8000' + request.get_full_path()
    redirect_uri = 'http://127.0.0.1:8000/callback'
    scope = 'openid email profile'
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    token = oauth.fetch_token(
        'http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/token',
        authorization_response=response,
        client_secret=client_secret)

    payload = {
        "client_id": "lox",
        "client_secret": "gBSc7w7Iaen3IU2CvBS50jkSQRUDdLIa",
        "token": token['access_token'],
        "Content-Type": "application/x-www-form-urlencoded",
    }
    http = "http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/token/introspect/"
    userinfo = requests.post(http, data=payload)
    userinfo = userinfo.json()
    print(userinfo)
    print(userinfo['username'])
    print(userinfo['sub'])
    print(userinfo['realm_access']['roles'])

    try:
        keycloak_user = KeycloakUser.objects.get(keycloak_id=userinfo['sub'])
    except ObjectDoesNotExist:
        user = User.objects.create_user(username=userinfo['username'])
        user.save()
        keycloak_user = KeycloakUser()
        keycloak_user.user = user
        keycloak_user.keycloak_id = userinfo['sub']
        keycloak_user.save()

    request.content_params['token'] = token['access_token']
    request.content_params['user_id'] = keycloak_user.user_id

    user = authenticate(request)
    login(request, user)
    request.content_params.clear()
    return redirect('/')
