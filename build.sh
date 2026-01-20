#!/usr/bin/env bash
# exit on error
set -o errexit

echo "🔧 Installing dependencies..."
pip install --upgrade pip
pip install -r requirements.txt

echo "📦 Collecting static files..."
python manage.py collectstatic --no-input

echo "🗄️ Running migrations..."
python manage.py migrate

echo "📁 Ensuring media directories exist..."
python manage.py ensure_media_dirs

echo "👤 Creating superuser (if environment variables are set)..."
python manage.py create_superuser

echo "✅ Build completed successfully!"
