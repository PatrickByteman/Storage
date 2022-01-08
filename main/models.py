from django.db import models


class Storage(models.Model):
    name = models.CharField(max_length=50)
    description = models.TextField()
    file = models.FileField(upload_to='uploads/%Y/%m/%d')


class Settings(models.Model):
    name = models.CharField(max_length=128)


class SAT(models.Model):
    token = models.JSONField()


class Events(models.Model):
    event = models.JSONField()
