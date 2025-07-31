from django.db import models

# Create your models here.

from django.db import models

class Product(models.Model):
    title = models.CharField(max_length=255)
    link = models.URLField()
    price = models.CharField(max_length=50)
