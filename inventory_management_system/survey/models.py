from django.db import models

# Create your models here.


class Survey(models.Model):
    servey_id = models.CharField(max_length=33,null=False)
    collector_id = models.CharField(max_length=33)
    