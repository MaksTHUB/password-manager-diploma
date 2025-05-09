# Generated by Django 5.1.5 on 2025-03-08 08:13

import django.db.models.deletion
from django.conf import settings
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('passwords', '0008_userprofile_failed_login_attempts_and_more'),
    ]

    operations = [
        migrations.CreateModel(
            name='LoginHistory',
            fields=[
                ('id', models.BigAutoField(auto_created=True, primary_key=True, serialize=False, verbose_name='ID')),
                ('ip_address', models.GenericIPAddressField(verbose_name='IP-адрес')),
                ('user_agent', models.TextField(verbose_name='User-Agent (браузер)')),
                ('timestamp', models.DateTimeField(auto_now_add=True, verbose_name='Время входа')),
                ('success', models.BooleanField(default=False, verbose_name='Успешный вход')),
                ('user', models.ForeignKey(on_delete=django.db.models.deletion.CASCADE, related_name='login_history', to=settings.AUTH_USER_MODEL)),
            ],
        ),
    ]
