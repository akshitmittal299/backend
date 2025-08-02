from allauth.socialaccount.adapter import DefaultSocialAccountAdapter
from django.contrib.auth import get_user_model
from .stripe_utils import create_stripe_customer  # adjust import to your project structure
from .models import StripeCustomer  # adjust if this model is elsewhere

User = get_user_model()

class CustomSocialAccountAdapter(DefaultSocialAccountAdapter):
    def save_user(self, request, sociallogin, form=None):
        user = super().save_user(request, sociallogin, form)

        if not user.is_verified:
            user.is_verified = True
            user.save()

        if not StripeCustomer.objects.filter(user=user).exists():
            stripe_id = create_stripe_customer(user.email)
            StripeCustomer.objects.create(user=user, stripe_customer_id=stripe_id)

        return user
