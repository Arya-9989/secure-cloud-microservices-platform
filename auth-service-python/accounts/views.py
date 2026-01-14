from django.shortcuts import render
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from rest_framework_simplejwt.tokens import RefreshToken
from .permissions import IsAdmin, IsUser, IsService, IsAdminOrService
from .serializers import LoginSerializer
from rest_framework.permissions import IsAuthenticated

class LoginView(APIView):
    permission_classes = [AllowAny]

    def post(self, request):
        serializer = LoginSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)

        user = serializer.validated_data['user']
        refresh = RefreshToken.for_user(user)

        return Response({
            "access": str(refresh.access_token),
            "refresh": str(refresh),
            "role": user.role,
            "email": user.email
        }, status=status.HTTP_200_OK)

class AdminOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsAdmin]

    def get(self, request):
        return Response({
            "message": "Hello ADMIN, you have full access."
        })


class UserOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsUser]

    def get(self, request):
        return Response({
            "message": "Hello USER, limited access granted."
        })


class ServiceOnlyView(APIView):
    permission_classes = [IsAuthenticated, IsService]

    def get(self, request):
        return Response({
            "message": "Hello SERVICE, inter-service access granted."
        })


class AdminOrServiceView(APIView):
    permission_classes = [IsAuthenticated, IsAdminOrService]

    def get(self, request):
        return Response({
            "message": "ADMIN or SERVICE access successful."
        })
    
class InternalHealthCheckView(APIView):
    permission_classes = [IsAuthenticated, IsService]

    def get(self, request):
        return Response({
            "status": "Auth service healthy",
            "service": "auth-service"
        })
