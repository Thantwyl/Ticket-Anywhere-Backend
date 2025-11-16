from django.urls import path, include
from rest_framework.routers import DefaultRouter
from rest_framework_simplejwt.views import TokenObtainPairView, TokenRefreshView
from .views import BannerViewSet, CategoryViewSet, EventViewSet, CustomerViewSet, OrderViewSet, TicketViewSet, UserRegisterView, custom_login, VerifyEmailOTPView, ResendOTPView, ForgotPasswordView, ResetPasswordView

router = DefaultRouter()
router.register(r'customers', CustomerViewSet, basename='customer')
router.register(r'banners', BannerViewSet, basename='banner')
router.register(r'categories', CategoryViewSet, basename='category')
router.register(r'events', EventViewSet, basename='event')
router.register(r'orders', OrderViewSet, basename='order')
router.register(r'tickets', TicketViewSet, basename='ticket')

urlpatterns = [
    path('', include(router.urls)),
    path('auth/register/', UserRegisterView.as_view(), name='user_register'),
    path('auth/verify-email/', VerifyEmailOTPView.as_view(), name='verify_email_otp'),
    path('auth/resend-otp/', ResendOTPView.as_view(), name='resend_otp'),
    path('auth/login/', custom_login, name='login'),
    path('auth/refresh/', TokenRefreshView.as_view(), name='token_refresh'),
    path('auth/forgot-password/', ForgotPasswordView.as_view(), name='forgot_password'),
    path('auth/reset-password/', ResetPasswordView.as_view(), name='reset_password'),
]