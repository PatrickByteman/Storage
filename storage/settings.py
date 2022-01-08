"""
Django settings for storage project.

Generated by 'django-admin startproject' using Django 3.1.6.

For more information on this file, see
https://docs.djangoproject.com/en/3.1/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/3.1/ref/settings/
"""
from pathlib import Path

# Build paths inside the project like this: BASE_DIR / 'subdir'.
BASE_DIR = Path(__file__).resolve().parent.parent


# Quick-start development settings - unsuitable for production
# See https://docs.djangoproject.com/en/3.1/howto/deployment/checklist/

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'kdpg$3w+vy^1i*y7=g%8g1jxr@wo5ql!lx8p82(kw0-jkqgd9v'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = [
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',

    'main',
    'bootstrap4',
    'crispy_forms',
    'social_django',
    'mozilla_django_oidc',
]

MIDDLEWARE = [
    'django.middleware.security.SecurityMiddleware',
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
]


KEYCLOAK_OIDC_PROFILE_MODEL = 'django_keycloak.OpenIdConnectProfile'


ROOT_URLCONF = 'storage.urls'

TEMPLATES = [
    {
        'BACKEND': 'django.template.backends.django.DjangoTemplates',
        'DIRS': [
            'main/templates'
        ],
        'APP_DIRS': True,
        'OPTIONS': {
            'context_processors': [
                'django.template.context_processors.debug',
                'django.template.context_processors.request',
                'django.contrib.auth.context_processors.auth',
                'django.contrib.messages.context_processors.messages',

                'social_django.context_processors.backends',
                'social_django.context_processors.login_redirect',
            ],
        },
    },
]

WSGI_APPLICATION = 'storage.wsgi.application'


# Database
# https://docs.djangoproject.com/en/3.1/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.sqlite3',
        'NAME': BASE_DIR / 'db.sqlite3',
    }
}


# Password validation
# https://docs.djangoproject.com/en/3.1/ref/settings/#auth-password-validators

AUTH_PASSWORD_VALIDATORS = [
    {
        'NAME': 'django.contrib.auth.password_validation.UserAttributeSimilarityValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.MinimumLengthValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.CommonPasswordValidator',
    },
    {
        'NAME': 'django.contrib.auth.password_validation.NumericPasswordValidator',
    },
]


# Internationalization
# https://docs.djangoproject.com/en/3.1/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# Static files (CSS, JavaScript, Images)
# https://docs.djangoproject.com/en/3.1/howto/static-files/
LOGOUT_REDIRECT_URL = 'http://127.0.0.1:8000/'
STATIC_URL = '/static/'
STATICFILES_DIRS = [
    'static'
]

CRISPY_TEMPLATE_PACK = 'bootstrap4'

SOCIAL_AUTH_URL_NAMESPACE = 'social'
SOCIAL_AUTH_KEYCLOAK_KEY = 'lox'
SOCIAL_AUTH_KEYCLOAK_SECRET = '2d8c1bab-b75a-447f-bf7b-72374bfc68c0'
SOCIAL_AUTH_KEYCLOAK_PUBLIC_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh7Bc+s/pbPF02ZOMc6VRVsqpwHoMgGNasNOzzen0pl8zISsZGMCWL/Irhq9X+mCSG2y1jMhFd14gEMZjU5CBN1Dblddz4MQF2MrbsIxOOJrtionPFrMHgiLXExWH9yWetc8rfbfEnzuNCj/mhykQvxq9II0Lz24L7/5Wb45YGNcjfMNiY7mv1r+8o+EKWwMkSGWvykKfNFOzIQqLC4+z++IMxnt+x4JeFSdOxT1sg2jNd+OumUGIF0/bLIca6uQthHBXGfkofTCiONq7YWg86Dzwr6dfWpKopc9QQh4ALvG1Y572Cja4Fi222nYJMf1DY2eNSWW63l2r00G6Fz1fywIDAQAB'
#OIDC_RP_IDP_SIGN_KEY = 'MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAh7Bc+s/pbPF02ZOMc6VRVsqpwHoMgGNasNOzzen0pl8zISsZGMCWL/Irhq9X+mCSG2y1jMhFd14gEMZjU5CBN1Dblddz4MQF2MrbsIxOOJrtionPFrMHgiLXExWH9yWetc8rfbfEnzuNCj/mhykQvxq9II0Lz24L7/5Wb45YGNcjfMNiY7mv1r+8o+EKWwMkSGWvykKfNFOzIQqLC4+z++IMxnt+x4JeFSdOxT1sg2jNd+OumUGIF0/bLIca6uQthHBXGfkofTCiONq7YWg86Dzwr6dfWpKopc9QQh4ALvG1Y572Cja4Fi222nYJMf1DY2eNSWW63l2r00G6Fz1fywIDAQAB'
SOCIAL_AUTH_KEYCLOAK_AUTHORIZATION_URL = \
    'http://localhost:8080/auth/realms/demo/protocol/openid-connect/auth/'
SOCIAL_AUTH_KEYCLOAK_ACCESS_TOKEN_URL = \
    'http://localhost:8080/auth/realms/demo/protocol/openid-connect/token/'
SOCIAL_AUTH_LOGIN_REDIRECT_URL = 'http://127.0.0.1:8000/'
SOCIAL_AUTH_KEYCLOAK_ID_KEY = 'email'


AUTHENTICATION_BACKENDS = [
    'social_core.backends.keycloak.KeycloakOAuth2',
    'mozilla_django_oidc.auth.OIDCAuthenticationBackend',
    'django.contrib.auth.backends.ModelBackend',
]

SOCIAL_AUTH_PIPELINE = (
    'social_core.pipeline.social_auth.social_details',
    'social_core.pipeline.social_auth.social_uid',
    'social_core.pipeline.social_auth.social_user',
    'social_core.pipeline.user.get_username',
    'social_core.pipeline.social_auth.associate_by_email',
    'social_core.pipeline.user.create_user',
    'social_core.pipeline.social_auth.associate_user',
    'social_core.pipeline.social_auth.load_extra_data',
    'social_core.pipeline.user.user_details',
    'social_core.pipeline.social_auth.load_extra_data',
)


OIDC_AUTH_URI = 'http://localhost:8080/auth/realms/demo'

LOGIN_REDIRECT_URL = 'http://127.0.0.1:8000/'

OIDC_RP_SIGN_ALGO = 'RS256'
OIDC_RP_CLIENT_ID = 'lox'
OIDC_RP_CLIENT_SECRET = "394bcd36-b576-42e2-80ae-d349eef941b9"
OIDC_RP_SCOPES = 'openid email profile'
OIDC_PERSISTENT_USER = False
OIDC_CREATE_USER = True

# Keycloak-specific (as per http://KEYCLOAK_SERVER/auth/realms/REALM/.well-known/openid-configuration)
OIDC_OP_AUTHORIZATION_ENDPOINT = OIDC_AUTH_URI + '/protocol/openid-connect/auth'
OIDC_OP_TOKEN_ENDPOINT = OIDC_AUTH_URI + '/protocol/openid-connect/token'
OIDC_OP_USER_ENDPOINT = OIDC_AUTH_URI + '/protocol/openid-connect/userinfo'

OIDC_OP_JWKS_ENDPOINT = 'http://localhost:8080/auth/realms/demo/protocol/openid-connect/certs'

