from django.contrib.auth import get_user_model
from rest_framework.decorators import api_view
from rest_framework.response import Response
from rest_framework import status

@api_view(['POST'])
def create_superuser(request):
    username = request.data.get('username')
    password = request.data.get('password')
    email = request.data.get('email')
    if not (username and password and email):
        return Response({'error': 'Missing fields'}, status=status.HTTP_400_BAD_REQUEST)
    User = get_user_model()
    if User.objects.filter(username=username).exists():
        return Response({'error': 'User exists'}, status=status.HTTP_400_BAD_REQUEST)
    User.objects.create_superuser(username=username, password=password, email=email)
    return Response({'success': 'Superuser created'}, status=status.HTTP_201_CREATED)