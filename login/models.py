from django.db import models

# Create your models here.
class Account(models.Model):
    username = models.CharField(max_length=100, unique=True)
    hashed_password = models.CharField(max_length=256)

    def __str__(self):
        return self.username