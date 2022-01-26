from django.shortcuts import render, redirect
from django.core.exceptions import ObjectDoesNotExist
from django.contrib.auth.decorators import login_required
from django.utils.decorators import method_decorator
from django.contrib.auth.models import User
from django.views import View
from main.models import KeycloakUser
from main.models import TypeFilter
from storage.settings import KEYCLOAK_CLIENT_SECRET
from keycloak.keycloak import Keycloak
from requests_oauthlib import OAuth2Session
import requests, datetime, ast
import os
from django.contrib.auth import authenticate, login
os.environ['OAUTHLIB_INSECURE_TRANSPORT'] = '1'


def index_page(request):
    context = {
        'pagename': 'Главная',
    }
    return render(request, 'pages/index.html', context)


def auth(request):
    return render(request, '')


class CreateFilter(View):
    context = {
        'pagename': 'New Filter'
    }

    def get(self, request):
        return render(request, 'pages/events/create_filter.html', self.context)

    def post(self, request):
        form = request.POST
        filter = TypeFilter()
        filter.name = form['name']
        filter.types = form.getlist('types-select')
        filter.save()
        return render(request, 'pages/events/create_filter.html', self.context)


class EventsView(View):
    keycloak = Keycloak()

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
        selected_users = form.getlist('users')
        if selected_users:
            users = []
            for user in selected_users:
                users.append(ast.literal_eval(user))
        else:
            if form['for_name'] == '0':
                users = self.keycloak.get_users_by_username(form['name'])
            else:
                users = self.keycloak.get_user_by_userid(form['name'])
        return users

    def get_events(self, form, users):
        types = form.getlist('types-select')
        if users:
            self.context['events'] = []
            for user in users:
                self.context['events'].append(
                    self.keycloak.get_user_events(form['dateFrom'], form['dateTo'], user['id'], types))
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
        users = self.get_users(form)
        self.get_events(form, users)
        self.get_extra_context(form)
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
    client_secret = KEYCLOAK_CLIENT_SECRET
    response = 'http://127.0.0.1:8000' + request.get_full_path()
    redirect_uri = 'http://127.0.0.1:8000/callback'
    scope = 'openid email profile'
    oauth = OAuth2Session(client_id, redirect_uri=redirect_uri, scope=scope)
    token = oauth.fetch_token(
        'http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/token',
        authorization_response=response,
        client_secret=client_secret)

    payload = {
        'client_id': 'lox',
        'client_secret': KEYCLOAK_CLIENT_SECRET,
        'token': token['access_token'],
        'Content-Type': 'application/x-www-form-urlencoded',
    }
    http = "http://127.0.0.1:8080/auth/realms/demo/protocol/openid-connect/token/introspect/"
    userinfo = requests.post(http, data=payload)
    userinfo = userinfo.json()

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
