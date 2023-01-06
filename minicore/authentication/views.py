from django.shortcuts import render, redirect
from django.views import View
import json
from django.http import JsonResponse
from django.contrib.auth.models import User
from validate_email import validate_email
from django.contrib import messages
from django.core.mail import EmailMessage
from django.urls import reverse
from .utils import token_generator
from django.contrib import auth
from django.contrib.auth.tokens import PasswordResetTokenGenerator

import threading

from django.utils.encoding import force_bytes, force_str, DjangoUnicodeDecodeError
from django.utils.http import urlsafe_base64_encode, urlsafe_base64_decode
from django.contrib.sites.shortcuts import get_current_site
# Create your views here.

class EmailThread(threading.Thread):
    def __init__(self, email):
        self.email=email
        threading.Thread.__init__(self)

    def run(self):
        self.email.send(fail_silently=False)


class EmailValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        email = data['email']

        if not validate_email(email):
            return JsonResponse({'email_error': 'El correo electrónico es inválido'}, status=400)

        if User.objects.filter(email=email).exists():
            return JsonResponse({'email_error': 'El correo electrónico ya existe dentro del sistema'}, status=409)

        return JsonResponse({'email_valid': True})


class RegistrationView(View):
    def get(self, request):
        return render(request, 'authentication/register.html')

    def post(self, request):
        # GET USER DATA
        # VALIDATE
        # create a user account

        username = request.POST['username']
        email = request.POST['email']
        password = request.POST['password']

        context = {
            'fieldValues': request.POST
        }

        if not User.objects.filter(username=username).exists():
            if not User.objects.filter(email=email).exists():
                if len(password) < 6:
                    messages.error(
                        request, 'La contrasena debe tener al menos 6 caracteres')
                    return render(request, 'authentication/register.html', context)

                user = User.objects.create_user(username=username, email=email)
                user.set_password(password)
                user.is_active = False
                user.save()
                current_site = get_current_site(request)
                email_body = {
                    'user': user,
                    'domain': current_site.domain,
                    'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                    'token': token_generator.make_token(user),
                }

                link = reverse('activate', kwargs={
                               'uidb64': email_body['uid'], 'token': email_body['token']})

                email_subject = 'Activa tu cuenta'

                activate_url = 'http://'+current_site.domain+link

                email = EmailMessage(
                    email_subject,
                    'Hola '+user.username + ', por favor sigue el link para activar tu cuenta \n'+activate_url,
                    'noreply@semycolon.com',
                    [email],
                )
                EmailThread(email).start()
                messages.success(request, 'La cuenta fue creada con exito')
                return render(request, 'authentication/register.html')

        return render(request, 'authentication/register.html')


class VerificationView(View):
    def get(self, request, uidb64, token):

        try:
            id = force_str(urlsafe_base64_decode(uidb64))
            user = User.objects.get(pk=id)

            if not token_generator.check_token(user, token):
                return redirect('login'+'?message='+'El usuario ya se encuentra activo')

            if user.is_active:
                return redirect('login')
            user.is_active = True
            user.save()

            messages.success(request, 'La cuenta se ha activado con exito')
            return redirect('login')

        except Exception as ex:
            pass

        return redirect('login')


class LoginView(View):
    def get(self, request):
        return render(request, 'authentication/login.html')

    def post(self, request):
        username = request.POST['username']
        password = request.POST['password']

        if username and password:
            user = auth.authenticate(username=username, password=password)
            if user:
                if user.is_active:
                    auth.login(request, user)
                    messages.success(
                        request, 'Bienvenido '+user.username+', ya te encuentras dentro del sistema')
                    return redirect('GastApp')
                messages.error(
                    request, 'Tu cuenta todavia no ha sido activada, por favor revisa tu correo')
                return render(request, 'authentication/login.html')
            messages.error(
                request, 'Las credenciales de inicio de sesion no son validas, por favor intenta de nuevo')
            return render(request, 'authentication/login.html')
        messages.error(
            request, 'Por favor llena todos los campos de inicio de sesion')
        return render(request, 'authentication/login.html')


class UsernameValidationView(View):
    def post(self, request):
        data = json.loads(request.body)
        username = data['username']

        if not str(username).isalnum():
            return JsonResponse({'username_error': 'El nombre de usuario solo puede contener caracteres alfanuméricos'}, status=400)

        if User.objects.filter(username=username).exists():
            return JsonResponse({'username_error': 'El nombre de usuario ya existe dentro del sistema'}, status=409)

        return JsonResponse({'username_valid': True})


class LogoutView(View):
    def post(self, request):
        auth.logout(request)
        messages.success(request, 'Ha cerrado sesion en el sistema')
        return redirect('login')


class RequestPasswordResetEmail(View):
    def get(self, request):
        return render(request, 'authentication/reset-password.html')

    def post(self, request):
        email = request.POST['email']
        context = {
            'values': request.POST
        }

        if not validate_email(email):
            messages.error(request, 'Por favor ingresa un correo valido')
            return render(request, 'authentication/reset-password.html', context)

        current_site = get_current_site(request)
        user=User.objects.filter(email=email)
        if user.exists():
            email_contents = {
            'user': user[0],
            'domain': current_site.domain,
            'uid': urlsafe_base64_encode(force_bytes(user[0].pk)),
            'token': PasswordResetTokenGenerator().make_token(user[0]),
            }

            link = reverse('reset-user-password', kwargs={
                'uidb64': email_contents['uid'], 'token': email_contents['token']})

            email_subject = 'Restablecimiento de contrasena'

            reset_url = 'http://'+current_site.domain+link

            email = EmailMessage(
                email_subject,
                'Hola, por favor sigue el link para restablecer la contrasena \n'+reset_url,
                'noreply@semycolon.com',
                [email],
            )
            EmailThread(email).start()

        messages.success(
            request, 'Se te ha enviado un correo con el restablecimiento')

        return render(request, 'authentication/reset-password.html')

class CompletePasswordReset(View):
    def get(self, request, uidb64, token):
        
        
        try:
            user_id=force_str(urlsafe_base64_decode(uidb64)) 
            user=User.objects.get(pk=user_id)

            if not PasswordResetTokenGenerator().check_token(user, token):
                messages.info(request,'El link usado es invalido, por favor solicita uno nuevo')
                return render(request, 'authentication/reset-password.html')
        except Exception as identifier:
            pass
        
        context={
            'uidb64':uidb64,
            'token':token
        }
        return render(request, 'authentication/set-new-password.html', context)

    def post(self, request, uidb64, token):
        context={
            'uidb64':uidb64,
            'token':token
        }

        password=request.POST['password']
        password2=request.POST['password2']

        if password != password2:
            messages.error(request, 'Las contrasenas no coinciden')
            return render(request, 'authentication/set-new-password.html', context)

        if len(password) < 6:
            messages.error(request, 'Las contrasena es muy corta')
            return render(request, 'authentication/set-new-password.html', context)

        try:
            user_id=force_str(urlsafe_base64_decode(uidb64)) 
            user=User.objects.get(pk=user_id)
            user.set_password(password)
            user.save()

            messages.success(request,'La contrasena ha sido restablecida, ya puedes iniciar sesion')
            return redirect('login')
        except Exception as identifier:
            messages.info(request,'Algo sucedio mal')
            return render(request, 'authentication/set-new-password.html', context)
        
        #return render(request, 'authentication/set-new-password.html', context)