# Generated by Django 4.2.7 on 2023-12-05 20:22

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0006_rename_name_permission_permission_type'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='user',
            name='permission',
        ),
        migrations.AddField(
            model_name='user',
            name='permission',
            field=models.ManyToManyField(to='api.permission'),
        ),
    ]
