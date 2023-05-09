from django.contrib.auth.backends import ModelBackend

from .models import User


class MobileBackend(ModelBackend):
    def authenticate(self, request, phone=None, password=None, **kwargs):
        try:
            user = User.objects.get(phone=phone)
        except User.DoesNotExist:
            # difference between an existing and a nonexistent user (#20760).
            User().set_password(password)
        else:
            if user.check_password(password) and self.user_can_authenticate(user):
                return user

    def user_can_authenticate(self, user):
        is_registered = getattr(user, 'is_registered', False)
        return super(MobileBackend, self).user_can_authenticate(user) and is_registered