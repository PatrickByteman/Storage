"""storage URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/3.1/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  path('', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  path('', Home.as_view(), name='home')
Including another URLconf
    1. Import the include() function: from django.urls import include, path
    2. Add a URL to urlpatterns:  path('blog/', include('blog.urls'))
"""
from django.conf.urls import url, include
from django.contrib import admin
from django.urls import path
from main import views
from django.contrib.auth import views as auth_views


urlpatterns = [
    url('', include('social_django.urls', namespace='social')),
    path('admin/', admin.site.urls),
    path('', views.index_page, name='index'),
    path('search/', views.get_events, name='search'),
    path('create/', views.CreateFile.as_view(), name='create'),
    path('login/', views.auth, name="test"),
    path('events/', views.get_events, name='events'),
    path('userinfo/', views.get_events, name='userinfo'),
    #path('authorize', views.oidc_login, name='authorize'),
    #path('callback', views.callback, name='callback'),

    path('logout/', auth_views.LogoutView.as_view(), name='logout'),
    path('oidc/', include('keycloak_oidc.urls')),
]
