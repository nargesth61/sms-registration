# Generated by Django 4.2.1 on 2023-05-09 08:26

import django.core.validators
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('membership', '0007_alter_user_phone'),
    ]

    operations = [
        migrations.AlterField(
            model_name='user',
            name='phone',
            field=models.CharField(max_length=14, unique=True, validators=[django.core.validators.RegexValidator(message='The phone number must be 10 digits.', regex='^\\d{10}')]),
        ),
    ]