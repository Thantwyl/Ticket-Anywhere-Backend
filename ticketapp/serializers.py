from rest_framework import serializers
from django.contrib.auth import get_user_model
from django.utils import timezone
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

class TicketCreateSerializer(serializers.ModelSerializer):
    """
    Serializer for regular users creating tickets
    Only allows basic fields that users should control
    """
    class Meta:
        model = Ticket
        fields = [
            'passport_name',
            'facebook_name',
            'member_code',
            'priority_date',
            'fst_pt',
            'snd_pt',
            'trd_pt',
            'event'
        ]
    
    def create(self, validated_data):
        """ Create single ticket with its own order """       
        event = validated_data.get('event')
        customer = self.context['request'].user       
        # Create order for this ticket
        order = Order.objects.create(
            customer=customer,
            event=event,
            order_time=timezone.now()
        )        
        # Set default values for ticket
        validated_data['order'] = order
        validated_data['status'] = 'pending'
        validated_data['refund_status'] = 'none'
        
        return super().create(validated_data)

class TicketBatchCreateSerializer(serializers.Serializer):
    """ Serializer for creating multiple tickets in one order (same purchase session) """
    event = serializers.PrimaryKeyRelatedField(queryset=Event.objects.all())
    tickets = TicketCreateSerializer(many=True)
    
    def create(self, validated_data):
        """ Create one order with multiple tickets for same purchase session """
        event = validated_data['event']
        tickets_data = validated_data['tickets']
        customer = self.context['request'].user       
        # Create ONE order for this purchase session
        order = Order.objects.create(
            customer=customer,
            event=event,
            order_time=timezone.now()
        )        
        # Create all tickets for this order
        created_tickets = []
        for ticket_data in tickets_data:
            ticket = Ticket.objects.create(
                order=order,
                event=event,
                status='pending',
                refund_status='none',
                **ticket_data
            )
            created_tickets.append(ticket)
        
        return {
            'order': order,
            'tickets': created_tickets
        }

class TicketViewSerializer(serializers.ModelSerializer):
    """
    Serializer for users viewing their own tickets
    Only shows basic user info - no admin fields like status/payment
    """
    customer_name = serializers.CharField(source='order.customer.name', read_only=True)
    customer_email = serializers.CharField(source='order.customer.email', read_only=True)
    event_name = serializers.CharField(source='event.event_name', read_only=True)
    
    class Meta:
        model = Ticket
        fields = [
            'id',
            'passport_name',
            'facebook_name',
            'member_code',
            'priority_date',
            'fst_pt',
            'snd_pt',
            'trd_pt',
            'event',
            'event_name',
            'customer_name',
            'customer_email',
        ]
        # No admin fields visible to regular users

class AdminTicketSerializer(serializers.ModelSerializer):
    """Serializer for admin/staff - can modify everything""" 
    customer_name = serializers.CharField(source='order.customer.name', read_only=True)
    customer_email = serializers.CharField(source='order.customer.email', read_only=True)
    event_name = serializers.CharField(source='event.event_name', read_only=True)
    
    class Meta:
        model = Ticket
        fields = '__all__'  # All fields available for admin
        
    def validate(self, data):
        """ Admin validation with proper business rules """
        status = data.get('status', self.instance.status if self.instance else 'pending')
        refund_status = data.get('refund_status', self.instance.refund_status if self.instance else 'none')
       
        # Validation rules
        if status == 'paid' and not all([data.get('customer_payment'), data.get('payment_date')]):
            raise serializers.ValidationError("customer_payment and payment_date are required for 'paid' status.")
            
        if status == 'complete' and not all([data.get('selling_price'), data.get('zone'), data.get('row'), data.get('seat')]):
            raise serializers.ValidationError("selling_price, zone, row, and seat are required for 'complete' status.")
            
        if status == 'cancel':
            if refund_status not in ['in_process', 'refunded']:
                raise serializers.ValidationError("For 'cancel' status, refund_status must be 'in_process' or 'refunded'.")
        else:
            if refund_status != 'none':
                raise serializers.ValidationError("Refund status can only be set for 'cancel' status. Set to 'none' for other statuses.")
                
        return data