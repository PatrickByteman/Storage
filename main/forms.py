from django import forms
from django.contrib.auth.backends import UserModel
from main.models import Storage


class StorageSettings(forms.ModelForm):
    class Meta:
        model = Storage
        fields = ['name', 'description', 'file']
        widgets = {
            'name': forms.TextInput(attrs={
                'class': 'form-control',
                'id': 'question',
                'placeholder': "Name",
            }),
            'description': forms.Textarea(attrs={
                'class': 'form-control',
                'id': 'text',
                'placeholder': "Description",
            }),
            'file': forms.FileInput(attrs={
                'id': 'validationFile',
                'placeholder': "File",
            }),
        }


class UserSetting(forms.ModelForm):
    class Meta:
        model = UserModel
        fields = ['username', 'password']
        widgets = {
            'username': forms.TextInput(attrs={
                'class': 'form-control',
                'id': 'validationCustomUsername',
                'placeholder': "Имя пользователя",
            }),
            'password': forms.TextInput(attrs={
                'class': 'form-control',
                'id': 'validationCustomUsername',
                'placeholder': "Пароль",
            }),
            'first_name': forms.TextInput(attrs={
                'class': 'form-control',
                'id': 'validationCustom01',
                'placeholder': "Имя",
            }),
            'last_name': forms.TextInput(attrs={
                'class': 'form-control',
                'id': 'validationCustom02',
                'placeholder': "Фамилия",
            }),
            'email': forms.EmailInput(attrs={
                'class': 'form-control',
                'id': 'validationCustomEmail',
                'placeholder': "E-mail",
            }),
        }
