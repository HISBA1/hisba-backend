# Generated by Django 5.0.5 on 2024-06-18 16:40

import django.utils.timezone
from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0026_chatmessage'),
    ]

    operations = [
        migrations.AddField(
            model_name='storerequest',
            name='created_at',
            field=models.DateTimeField(auto_now_add=True, default=django.utils.timezone.now),
            preserve_default=False,
        ),
        migrations.DeleteModel(
            name='ChatMessage',
        ),
    ]
