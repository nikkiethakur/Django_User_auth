from django.urls import path
from .views import RegisterUserView, LoginUserView, ResetPasswordRequestView, ResetPasswordConfirmView, ProtectionView

urlpatterns = [
    path('register/', RegisterUserView.as_view(), name='register'),
    path('login/', LoginUserView.as_view(), name='login'),
    path('reset-password-request/', ResetPasswordRequestView.as_view(), name='reset_password_request'),
    path('reset-password-confirm/<uid>/<token>/', ResetPasswordConfirmView.as_view(), name='reset-password-confirm'),
    path('protection/', ProtectionView.as_view(), name='protection'),
]