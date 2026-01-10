from rest_framework import viewsets, permissions, generics, status
from django.contrib.auth import get_user_model
from .models import Banner, Category, Event, Customer, Order, Ticket
from .serializers import CustomerSerializer, BannerSerializer, CategorySerializer, EventSerializer, OrderSerializer, TicketCreateSerializer, TicketViewSerializer, AdminTicketSerializer, OTPVerificationSerializer, ResendOTPSerializer, ForgotPasswordSerializer, ResetPasswordSerializer
from .permissions import IsAdminOrReadOnly, TicketPermission, OrderPermission
from rest_framework.exceptions import PermissionDenied
from django.core.mail import send_mail
from django.conf import settings
from rest_framework.decorators import api_view, permission_classes, action
from rest_framework.response import Response
from rest_framework_simplejwt.tokens import RefreshToken
from django.http import HttpResponse
from datetime import datetime
import csv


Customer = get_user_model()

class CustomerViewSet(viewsets.ModelViewSet):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [permissions.IsAuthenticated]
    def get_queryset(self):
        user = self.request.user
        if user.is_staff or user.is_superuser:
            return Customer.objects.all() # admin can see all data
        return Customer.objects.filter(id=user.id)  # Customer sees only their own account
    def perform_update(self, serializer):
        user = self.request.user
        if not (user.is_staff or user.is_superuser) and serializer.instance != user.id:
            raise PermissionDenied("You cannot update another user's profile!!!")
        serializer.save()

class UserRegisterView(generics.CreateAPIView):
    queryset = Customer.objects.all()
    serializer_class = CustomerSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    def create(self ,request, *args, **kwargs):
        response = super().create(request, *args, **kwargs)
        user = Customer.objects.get(email=request.data['email'])
        # generate and send otp
        otp_code = user.generate_otp('verification')
        send_mail(
            'Verify your email - OTP code',
            f'Your verification code is: {otp_code}\n\nDo not share this code with anyone.',
            settings.EMAIL_HOST_USER,
            [user.email],
        )
        return Response({
            'message': 'Registration successful. Please verify your email using the OTP sent to your email address.',
            'email': user.email
        }, status=status.HTTP_201_CREATED)

class VerifyEmailOTPView(generics.GenericAPIView):
    serializer_class = OTPVerificationSerializer
    permission_class = [permissions.AllowAny]
    authentication_class = []
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp_code']
        try:
            user = Customer.objects.get(email=email)
        except Customer.DoesNotExist:
            return Response({'error': 'User not found.'}, status=status.HTTP_404_NOT_FOUND)
       
        if user.email_verified:
            return Response({"message": "Email already verified. You can login now."}, status=status.HTTP_200_OK)
        
        if user.verify_otp(otp_code, 'verification'):
            user.email_verified = True
            user.is_active = True
            user.clear_otp()
            return Response({"message": "Email verified successfully. You can now login."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired OTP code."}, status=status.HTTP_400_BAD_REQUEST)

class ResendOTPView(generics.GenericAPIView):
    serializer_class = ResendOTPSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)       
        email = serializer.validated_data['email']
        
        try:
            user = Customer.objects.get(email=email)
        except Customer.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if user.email_verified:
            return Response({"message": "Email already verified. You can login now."}, status=status.HTTP_200_OK)
        
        # Generate new OTP
        otp_code = user.generate_otp('verification')
        send_mail(
            'Verify Your Email - New OTP Code',
            f'Your new verification code is: {otp_code}\n\nThis code will expire in 10 minutes.\n\nDo not share this code with anyone.',
            settings.EMAIL_HOST_USER,
            [user.email],
        )       
        return Response({"message": "New OTP code sent to your email."}, status=status.HTTP_200_OK) 

class ForgotPasswordView(generics.GenericAPIView):
    serializer_class = ForgotPasswordSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)      
        email = serializer.validated_data['email']
        
        try:
            user = Customer.objects.get(email=email)
        except Customer.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if not user.email_verified:
            return Response({"error": "Please verify your email first."}, status=status.HTTP_403_FORBIDDEN)
        
        # Generate OTP for password reset
        otp_code = user.generate_otp('password_reset')
        send_mail(
            'Password Reset - OTP Code',
            f'Your password reset code is: {otp_code}\n\nThis code will expire in 10 minutes.\n\nIf you did not request this, please ignore this email.',
            settings.EMAIL_HOST_USER,
            [user.email],
        )       
        return Response({"message": "Password reset OTP sent to your email."}, status=status.HTTP_200_OK)

class ResetPasswordView(generics.GenericAPIView):
    serializer_class = ResetPasswordSerializer
    permission_classes = [permissions.AllowAny]
    authentication_classes = []
    def post(self, request):
        serializer = self.get_serializer(data=request.data)
        serializer.is_valid(raise_exception=True)      
        email = serializer.validated_data['email']
        otp_code = serializer.validated_data['otp_code']
        new_password = serializer.validated_data['new_password']
        
        try:
            user = Customer.objects.get(email=email)
        except Customer.DoesNotExist:
            return Response({"error": "User not found."}, status=status.HTTP_404_NOT_FOUND)
        
        if user.verify_otp(otp_code, 'password_reset'):
            user.set_password(new_password)
            user.clear_otp()
            return Response({"message": "Password reset successful. You can now login with your new password."}, status=status.HTTP_200_OK)
        else:
            return Response({"error": "Invalid or expired OTP code."}, status=status.HTTP_400_BAD_REQUEST)

# Custom login view that accepts email instead of username
@api_view(['POST'])
@permission_classes([permissions.AllowAny])
def custom_login(request):
    email = request.data.get('email')
    password = request.data.get('password')

    if not email or not password:
        return Response ({'error': 'Email and password are required'}, status=400)
    try:
        user = Customer.objects.get(email = email)
    except Customer.DoesNotExist:
        return Response({'error': 'Invalid credentials'}, status=401)
    
    if not user.check_password(password):
        return Response({'error': 'Invalid credentials'}, status=401)
    
    # Check if email is verified (if you implement email verification)
    if hasattr(user, 'email_verified') and not user.email_verified:
        return Response({'error': 'Please verify your email first'}, status=403)  
    # Generate tokens
    refresh = RefreshToken.for_user(user)

    return Response({
        'access_token': str(refresh.access_token),
        'refresh_token': str(refresh),
        'user': {
            'id': user.id,
            'email': user.email,
            'name': user.name,
            'is_staff': user.is_staff,
            'is_superuser': user.is_superuser
        }
    })

class BannerViewSet(viewsets.ModelViewSet):
    queryset = Banner.objects.all()
    serializer_class = BannerSerializer
    permission_classes = [IsAdminOrReadOnly]

class CategoryViewSet(viewsets.ModelViewSet):
    queryset = Category.objects.all()
    serializer_class = CategorySerializer
    permission_classes = [IsAdminOrReadOnly]

class EventViewSet(viewsets.ModelViewSet):
    queryset = Event.objects.all() 
    serializer_class = EventSerializer
    permission_classes = [IsAdminOrReadOnly]

# Order : Auto-generated bridge table - mainly for admin management
class OrderViewSet(viewsets.ModelViewSet):
    queryset = Order.objects.all()
    serializer_class = OrderSerializer
    permission_classes = [OrderPermission]
    
    def get_queryset(self):
        """ Admin sees all orders, customers see only their own """
        user = self.request.user
        if user.is_staff:
            return Order.objects.all().order_by('-order_time')
        return Order.objects.filter(customer=user).order_by('-order_time')
    
    def perform_create(self, serializer):
        """ Handle order creation - auto-link to current user """
        if self.request.user.is_staff: # Admin can create orders for any customer           
            serializer.save()
        else: # Customers create orders for themselves            
            serializer.save(customer=self.request.user)

# Ticket : Registered customers (limited access) and admin (full access)
class TicketViewSet(viewsets.ModelViewSet):
    queryset = Ticket.objects.all()
    permission_classes = [TicketPermission]
    
    def get_queryset(self):
        """ Admin sees all tickets, customers see only their own """
        user = self.request.user
        if user.is_staff:
            return Ticket.objects.all().order_by('-id') 
        return Ticket.objects.filter(order__customer=user).order_by('-id')
    
    def get_serializer_class(self):
        """ Return different serializers based on user type and action """
        user = self.request.user       
        if user.is_staff: # Admin gets full serializer for all operations          
            return AdminTicketSerializer
        else: # Regular customers get limited serializers            
            if self.action == 'create':
                return TicketCreateSerializer  # Limited fields for creation
            else:  # list, retrieve
                return TicketViewSerializer   # Limited fields for viewing
    
    def get_serializer(self, *args, **kwargs):
        kwargs['partial'] = True  # Allow partial updates
        return super().get_serializer(*args, **kwargs)
    
    def perform_create(self, serializer):
        """ Handle ticket creation - auto-creates order for customers """
        if self.request.user.is_staff: # Admin can create tickets with full control           
            serializer.save()
        else: # Customer creation - order auto-handled in TicketCreateSerializer           
            serializer.save()
    
    def perform_update(self, serializer):
        """ Only admin can update tickets """
        if not self.request.user.is_staff:
            raise PermissionDenied("Only administrators can update tickets.")
        serializer.save()
    
    def perform_destroy(self, instance):
        """ Only admin can delete tickets """
        if not self.request.user.is_staff:
            raise PermissionDenied("Only administrators can delete tickets.")
        instance.delete()

    @action(detail=False, methods=['get'], permission_classes=[permissions.IsAdminUser])
    def export_csv(self, request):
        """Export all tickets to CSV file - Admin only"""
        
        # Get all tickets with related data for better performance
        tickets = Ticket.objects.select_related(
            'order__customer', 'event'
        ).all().order_by('-id')
        
        # Create filename with current timestamp
        filename = f'tickets_export_{datetime.utcnow().strftime("%Y%m%d_%H%M%S")}.csv'
        
        # Create HTTP response with CSV content type
        response = HttpResponse(content_type='text/csv')
        response['Content-Disposition'] = f'attachment; filename="{filename}"'
        
        # Create CSV writer
        writer = csv.writer(response)
        
        # Write header row
        writer.writerow([
            'Ticket ID',
            'Customer Name', 
            'Customer Email',
            'Event Name',
            'Event Location',
            'Passport Name',
            'Facebook Name',
            'Member Code',
            'Priority Date',
            'First Priority',
            'Second Priority', 
            'Third Priority',
            'Status',
            'Customer Payment',
            'Payment Date',
            'Selling Price',
            'Zone',
            'Row', 
            'Seat',
            'Refund Status',
            'Order Time',
            'Order ID'
        ])
        
        # Write data rows
        for ticket in tickets:
            writer.writerow([
                ticket.id,
                ticket.order.customer.name if ticket.order and ticket.order.customer else 'Unknown Customer',
                ticket.order.customer.email if ticket.order and ticket.order.customer else 'No Email',
                ticket.event.event_name if ticket.event else 'No Event',
                ticket.event.event_location if ticket.event else 'No Location',
                ticket.passport_name or '',
                ticket.facebook_name or '',
                ticket.member_code or '',
                ticket.priority_date if ticket.priority_date else '',
                ticket.fst_pt or '',
                ticket.snd_pt or '',
                ticket.trd_pt or '',
                ticket.status,
                ticket.customer_payment or '',
                ticket.payment_date if ticket.payment_date else '',
                ticket.selling_price or '',
                ticket.zone or '',
                ticket.row or '',
                ticket.seat or '',
                ticket.refund_status,
                ticket.order.order_time if ticket.order and ticket.order.order_time else 'No Order Time',
                ticket.order.id if ticket.order else 'No Order'
            ])
        
        return response
