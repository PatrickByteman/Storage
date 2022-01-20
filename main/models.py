from django.db import models
from django.contrib.auth.models import User


class KeycloakUser(models.Model):
    user = models.OneToOneField(to=User, on_delete=models.CASCADE)
    keycloak_id = models.CharField(max_length=128)


class TypeFilter(models.Model):
    name = models.CharField(max_length=128)
    types = models.JSONField()

# class Storage(models.Model):
#     name = models.CharField(max_length=50)
#     description = models.TextField()
#     file = models.FileField(upload_to='uploads/%Y/%m/%d')
#
#
#
#
# class SAT(models.Model):
#     token = models.JSONField()
#
#
# class Events(models.Model):
#     event = models.JSONField()
