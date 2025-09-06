import base64
import hashlib
import os
import logging
from urllib.parse import urlencode

from django.conf import settings
from django.shortcuts import render, redirect
from django.http import  JsonResponse
from django.contrib.auth import get_user_model, login, logout
from django.contrib import messages
from django.views.decorators.http import require_http_methods

import requests
from google.oauth2 import id_token
from google.auth.transport import requests as grequests

logger = logging.getLogger(__name__)
User = get_user_model()

def home(request):
    context = {
        'user_email': request.user.email if request.user.is_authenticated else None,
        'user_name': request.user.get_full_name() if request.user.is_authenticated else None,
    }
    return render(request, 'home.html', context)

def _b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).decode().rstrip("=")

def google_login(request):
    try:
        code_verifier = _b64url(os.urandom(40)) 
        code_challenge = _b64url(hashlib.sha256(code_verifier.encode()).digest())
        state = _b64url(os.urandom(32))

        request.session['code_verifier'] = code_verifier
        request.session['oauth_state'] = state

        params = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "response_type": "code",
            "scope": "openid email profile",
            "state": state,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "access_type": "offline",
            "include_granted_scopes": "true",
        }
        auth_url = "https://accounts.google.com/o/oauth2/v2/auth?" + urlencode(params)

        response = redirect(auth_url)
        
        cookie_kwargs = {
            'max_age': 600,
            'httponly': True,
            'samesite': 'Lax',
            'secure': not settings.DEBUG,
        }
        
        response.set_cookie('oauth_state', state, **cookie_kwargs)
        response.set_cookie('pkce_verifier', code_verifier, **cookie_kwargs)
        
        logger.info(f"Initiating Google OAuth for session: {request.session.session_key}")
        return response
        
    except Exception as e:
        logger.error(f"Error initiating Google login: {str(e)}")
        messages.error(request, "Failed to initiate Google login. Please try again.")
        return redirect('home')

def google_callback(request):
    try:
        error = request.GET.get("error")
        if error:
            error_description = request.GET.get("error_description", "Unknown error")
            logger.error(f"Google OAuth error: {error} - {error_description}")
            messages.error(request, f"Google authentication failed: {error_description}")
            return redirect('home')

        code = request.GET.get("code")
        returned_state = request.GET.get("state")
        
        if not code or not returned_state:
            logger.error("Missing authorization code or state parameter")
            messages.error(request, "Invalid response from Google. Please try again.")
            return redirect('home')

        expected_state = request.session.get('oauth_state') or request.COOKIES.get('oauth_state')
        if not expected_state or returned_state != expected_state:
            logger.error("Invalid or missing state parameter")
            messages.error(request, "Security validation failed. Please try again.")
            return redirect('home')

        code_verifier = request.session.get('code_verifier') or request.COOKIES.get('pkce_verifier')
        if not code_verifier:
            logger.error("Missing code verifier")
            messages.error(request, "Authentication state lost. Please try again.")
            return redirect('home')

        token_data = {
            "client_id": settings.GOOGLE_CLIENT_ID,
            "client_secret": settings.GOOGLE_CLIENT_SECRET,
            "code": code,
            "grant_type": "authorization_code",
            "redirect_uri": settings.GOOGLE_REDIRECT_URI,
            "code_verifier": code_verifier,
        }
        
        token_response = requests.post(
            "https://oauth2.googleapis.com/token",
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            data=token_data,
            timeout=30,
        )
        
        if token_response.status_code != 200:
            logger.error(f"Token exchange failed: {token_response.status_code} - {token_response.text}")
            messages.error(request, "Failed to authenticate with Google. Please try again.")
            return redirect('home')

        tokens = token_response.json()
        id_token_str = tokens.get("id_token")
        
        if not id_token_str:
            logger.error("No ID token received from Google")
            messages.error(request, "Authentication incomplete. Please try again.")
            return redirect('home')

        try:
            idinfo = id_token.verify_oauth2_token(
                id_token_str,
                grequests.Request(),
                settings.GOOGLE_CLIENT_ID,
            )
        except ValueError as e:
            logger.error(f"ID token verification failed: {str(e)}")
            messages.error(request, "Invalid authentication token. Please try again.")
            return redirect('home')

        email = idinfo.get("email")
        if not email:
            logger.error("No email found in ID token")
            messages.error(request, "Unable to retrieve email from Google. Please try again.")
            return redirect('home')

        user, created = User.objects.get_or_create(
            username=email,
            defaults={
                "email": email,
                "first_name": idinfo.get("given_name", ""),
                "last_name": idinfo.get("family_name", ""),
            }
        )
        
        updated_fields = []
        if user.email != email:
            user.email = email
            updated_fields.append('email')
        if user.first_name != idinfo.get("given_name", ""):
            user.first_name = idinfo.get("given_name", "")
            updated_fields.append('first_name')
        if user.last_name != idinfo.get("family_name", ""):
            user.last_name = idinfo.get("family_name", "")
            updated_fields.append('last_name')
            
        if updated_fields:
            user.save(update_fields=updated_fields)

        login(request, user)
        
        request.session.pop('oauth_state', None)
        request.session.pop('code_verifier', None)

        response = redirect('home')
        response.delete_cookie('oauth_state')
        response.delete_cookie('pkce_verifier')
        
        action = "registered" if created else "logged in"
        messages.success(request, f"Successfully {action} with Google!")
        logger.info(f"User {email} successfully {action}")
        
        return response
        
    except Exception as e:
        logger.error(f"Unexpected error in Google callback: {str(e)}")
        messages.error(request, "An unexpected error occurred. Please try again.")
        return redirect('home')

def logout_view(request):
    if request.user.is_authenticated:
        logger.info(f"User {request.user.email} logged out")
        logout(request)
        messages.success(request, "Successfully logged out!")
    return redirect('home')

@require_http_methods(["GET"])
def user_info(request):
    if not request.user.is_authenticated:
        return JsonResponse({"authenticated": False})
    
    return JsonResponse({
        "authenticated": True,
        "email": request.user.email,
        "first_name": request.user.first_name,
        "last_name": request.user.last_name,
        "full_name": request.user.get_full_name(),
    })