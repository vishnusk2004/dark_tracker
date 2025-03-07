from django.urls import path
from . import views

urlpatterns = [
    path("", views.about, name="about"),  # ✅ Shows the About page first
    path("home/", views.home, name="home"),  # ✅ Scanning feature
    path("scan/", views.home, name="scan"),  # ✅ New alias for scanning
    path("register/", views.register_user, name="register"),
    path("login/", views.login_user, name="login"),
    path("logout/", views.logout_user, name="logout"),
    path("dashboard/", views.dashboard, name="dashboard"),
    path("report/", views.report, name="report"),
]

