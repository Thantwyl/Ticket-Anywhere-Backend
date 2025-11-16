from rest_framework import serializers
from django.contrib.auth import get_user_model
from .models import Banner, Category, Event, Order, Ticket

Customer = get_user_model()

class CustomerSerializer(serializers.ModelSerializer):
    password = serializers.CharField(write_only=True)
    class Meta:
        model = Customer
        fields = ["id", "email", "name", "password", "is_staff", "is_superuser", "email_verified"]
        read_only_fields = ["is_staff", "is_superuser", "email_verified"]
    def create(self, validated_data):
        password = validated_data.pop("password", None)
        user = Customer(**validated_data)
        user.is_active = False  # User is inactive until email verification
        if password:
            user.set_password(password)
        user.save()
        return user
    
class OTPVerificationSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6, min_length=6)

class ResendOTPSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ForgotPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()

class ResetPasswordSerializer(serializers.Serializer):
    email = serializers.EmailField()
    otp_code = serializers.CharField(max_length=6, min_length=6)
    new_password = serializers.CharField(write_only=True, min_length=8)

class BannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = Banner
        fields = '__all__'

class CategorySerializer(serializers.ModelSerializer):
    class Meta:
        model = Category
        fields = '__all__'

class EventSerializer(serializers.ModelSerializer):
    class Meta:
        model = Event
        fields = '__all__'

class OrderSerializer(serializers.ModelSerializer):
    class Meta:
        model = Order
        fields = '__all__'

class TicketSerializer(serializers.ModelSerializer):
    class Meta:
        model = Ticket 
        fields = '__all__'