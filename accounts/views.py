from django.shortcuts import render, redirect
from .forms import RegistrationForm
from .models import Account
from django.contrib import messages
from django.http import HttpResponse
from django.contrib.auth.decorators import login_required
from django.contrib.auth import logout as auth_logout
from django.utils.http import urlsafe_base64_decode
from cart.models import Cart, CartItem

# Email Verification
from django.contrib.sites.shortcuts import get_current_site
from django.utils.http import urlsafe_base64_encode
from django.utils.encoding import force_bytes
from django.contrib.auth.tokens import default_token_generator
from django.template.loader import render_to_string
from django.core.mail import EmailMessage
from django.urls import reverse
from django.contrib import auth
from cart.views import _cart_id


def register(request):
    if request.method == 'POST':
        form = RegistrationForm(request.POST)
        if form.is_valid():
            first_name = form.cleaned_data['first_name']
            last_name = form.cleaned_data['last_name']
            email = form.cleaned_data['email']
            phone_number = form.cleaned_data['phone_number']
            password = form.cleaned_data['password']
            username = email.split("@")[0]

            user = Account.objects.create_user(first_name=first_name, last_name=last_name, email=email, username=username, password=password)
            user.phone_number = phone_number
            user.save()

            # User Activation
            current_site = get_current_site(request).domain
            mail_subject = 'Please activate your account'

            message = render_to_string('accounts/account_verification_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            to_email = email
            send_email = EmailMessage(mail_subject, message, to=[to_email])
            send_email.send()

            messages.success(request, 'Registration Successful. Please check your email for activation.')
            return redirect(reverse('login') + '?command=verification&email=' + email)
    else:
        form = RegistrationForm()

    context = {'form': form}
    return render(request, 'accounts/register.html', context)


def login(request):
    if request.method == 'POST':
        email = request.POST.get('email', '').strip()
        password = request.POST.get('password', '')
        user = auth.authenticate(email=email, password=password)
        if user is not None:
            
            try:
                cart = Cart.objects.get(cart_id=_cart_id(request))
                is_cart_item_exist = CartItem.objects.filter(cart=cart).exists()

                if is_cart_item_exist:
                    cart_item = CartItem.objects.filter(cart=cart)
                    for item in cart_item:
                        item.user = user
                        item.save()

            except Cart.DoesNotExist:
                pass
        
            auth.login(request, user)
            messages.success(request, "You're logged in successfully.")
            return redirect('store')

        else:
            messages.error(request, "Invalid email or password.")
            return redirect('login')

    return render(request, 'accounts/login.html')


@login_required(login_url='login')
def logout(request):
    auth_logout(request)
    messages.success(request, "You are logged out")
    return redirect('login')


def activate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        user.is_active = True
        user.save()
        messages.success(request, 'Congratulations! Your account has been activated.')
        return redirect('login')
    else:
        messages.error(request, "Invalid or expired activation link.")
        return redirect('register')


def forgotPassword(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        if not email:
            messages.error(request, "Please enter a valid email address.")
            return redirect('forgotPassword')

        if Account.objects.filter(email=email).exists():
            user = Account.objects.get(email=email)

            current_site = get_current_site(request).domain
            mail_subject = 'Please Reset Your Password'

            message = render_to_string('accounts/reset_password_email.html', {
                'user': user,
                'domain': current_site,
                'uid': urlsafe_base64_encode(force_bytes(user.pk)),
                'token': default_token_generator.make_token(user),
            })

            send_email = EmailMessage(mail_subject, message, to=[email])
            send_email.send()

            messages.success(request, "Password reset instructions have been sent to your email.")
            return redirect('forgotPassword')

        else:
            messages.error(request, "Account does not exist with this email.")
            return redirect('forgotPassword')

    return render(request, 'accounts/forgotPassword.html')


def resetpassword_validate(request, uidb64, token):
    try:
        uid = urlsafe_base64_decode(uidb64).decode()
        user = Account._default_manager.get(pk=uid)
    except (TypeError, ValueError, OverflowError, Account.DoesNotExist):
        user = None

    if user is not None and default_token_generator.check_token(user, token):
        request.session['uid'] = uid
        messages.success(request, 'Please reset your password.')
        return redirect('resetPassword')
    else:
        messages.error(request, "This link has expired or is invalid.")
        return redirect('forgotPassword')


def resetPassword(request):
    if request.method == 'POST':
        password = request.POST.get('password')
        confirm_password = request.POST.get('confirm_password')

        if password == confirm_password:
            uid = request.session.get('uid')
            user = Account.objects.get(pk=uid)
            user.set_password(password)
            user.save()

            messages.success(request, 'Password reset successfully.')
            return redirect('login')
        else:
            messages.error(request, "Passwords do not match.")
            return redirect('resetPassword')

    return render(request, 'accounts/resetPassword.html')



@login_required(login_url = 'login')
def dashboard(request):
    # orders = Order.objects.order_by('-created_at').filter(user_id=request.user.id, is_ordered=True)
    # orders_count = orders.count()

    # userprofile = UserProfile.objects.get(user_id=request.user.id)
    # context = {
    #     'orders_count': orders_count,
    #     'userprofile': userprofile,
    # }
    return render(request, 'accounts/dashboard.html')

