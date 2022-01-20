from django.contrib import admin
#from django.contrib.auth.admin import UserAdmin
from main.models import KeycloakUser
# Register your models here.

admin.site.register(KeycloakUser)
