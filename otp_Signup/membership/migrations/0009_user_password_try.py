# Generated by Django 4.2.1 on 2023-05-09 09:17

from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('membership', '0008_alter_user_phone'),
    ]

    operations = [
        migrations.AddField(
            model_name='user',
            name='password_try',
            field=models.IntegerField(default=3, max_length=2),
        ),
    ]
