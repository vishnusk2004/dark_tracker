from django.db import models
from django.contrib.auth.models import User

class ScanResult(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    url = models.URLField()
    xss = models.TextField(blank=True)
    sqli = models.TextField(blank=True)
    js = models.TextField(blank=True)
    rce = models.TextField(blank=True)
    form_vuln = models.TextField(blank=True)
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"Scan by {self.user.username} on {self.url}"
