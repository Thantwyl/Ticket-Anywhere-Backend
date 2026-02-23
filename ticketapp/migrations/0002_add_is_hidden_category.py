from django.db import migrations, models


class Migration(migrations.Migration):

    dependencies = [
        ("ticketapp", "0001_initial"),
    ]

    operations = [
        migrations.AddField(
            model_name="category",
            name="is_hidden",
            field=models.BooleanField(default=False),
        ),
    ]
