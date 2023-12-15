from django.urls import path
from . import views
urlpatterns = [
    path('oauth/dialog/',views.oauth_dialog),
    path('oauth/callback',views.get_oauth_code),
    path('',views.surveys)
]