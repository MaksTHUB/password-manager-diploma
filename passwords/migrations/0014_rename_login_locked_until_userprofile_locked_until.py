# Generated by Django 5.1.5 on 2025-03-11 20:06

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('passwords', '0013_userprofile_failed_login_attempts_and_more'),
    ]

    operations = [
        migrations.RenameField(
            model_name='userprofile',
            old_name='login_locked_until',
            new_name='locked_until',
        ),
    ]
