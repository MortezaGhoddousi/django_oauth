from django.contrib import admin
from django.urls import path
from . import views

urlpatterns = [
    path('admin/', admin.site.urls),
    path('', views.home, name='home'),
    path('google/login/', views.google_login, name='google_login'),
    path('google/auth/callback/', views.google_callback, name='google_callback'),
    path('logout/', views.logout_view, name='logout'),
    path('api/user/', views.user_info, name='user_info'),
]