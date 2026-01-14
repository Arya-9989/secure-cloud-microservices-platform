from django.contrib.auth.base_user import BaseUserManager


class UserManager(BaseUserManager):
    def create_user(self, email, password=None, role='USER'):
        if not email:
            raise ValueError("Email required")

        user = self.model(
            email=self.normalize_email(email),
            role=role
        )
        user.set_password(password)
        user.save()
        return user

    def create_superuser(self, email, password):
        user = self.create_user(email, password, role='ADMIN')
        user.is_staff = True
        user.is_superuser = True
        user.save()
        return user
