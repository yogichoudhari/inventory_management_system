# Generated by Django 4.2.7 on 2023-11-29 21:09

from django.db import migrations, models
import django.db.models.deletion


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0003_alter_user_account'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='account',
            field=models.ForeignKey(null=True, on_delete=django.db.models.deletion.SET_NULL, related_name='users', to='api.account'),
        ),
    ]
