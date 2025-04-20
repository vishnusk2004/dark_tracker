from django.urls import path
from . import views
from django.contrib.auth import views as auth_views

urlpatterns = [
    path("", views.about, name="about"),  # ✅ Shows the About page first
    path("home/", views.home, name="home"),  # ✅ Scanning feature
    path("scan/", views.home, name="scan"),  # ✅ New alias for scanning
    path("register/", views.register_user, name="register"),
    path("login/", views.login_user, name="login"),
    path("logout/", views.logout_user, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("report/", views.report, name="report"),

    path('reset-password/', auth_views.PasswordResetView.as_view(), name='password_reset'),
    path('reset-password-sent/', auth_views.PasswordResetDoneView.as_view(), name='password_reset_done'),
    path('reset/<uidb64>/<token>/', auth_views.PasswordResetConfirmView.as_view(), name='password_reset_confirm'),
    path('reset-password-complete/', auth_views.PasswordResetCompleteView.as_view(), name='password_reset_complete'),
]
