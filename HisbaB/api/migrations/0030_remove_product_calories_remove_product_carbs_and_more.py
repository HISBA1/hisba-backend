# Generated by Django 5.0.5 on 2024-06-21 02:15

from django.db import migrations


class Migration(migrations.Migration):

    dependencies = [
        ('api', '0029_product_calories_product_carbs_product_fat_and_more'),
    ]

    operations = [
        migrations.RemoveField(
            model_name='product',
            name='calories',
        ),
        migrations.RemoveField(
            model_name='product',
            name='carbs',
        ),
        migrations.RemoveField(
            model_name='product',
            name='fat',
        ),
        migrations.RemoveField(
            model_name='product',
            name='fiber',
        ),
        migrations.RemoveField(
            model_name='product',
            name='protein',
        ),
    ]
