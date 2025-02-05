# from . models import Cart , CartItem
# from .views import _cart_id

# def counter(request):
#     cart_count = 0
#     if 'admin' in request.path:
#         return {}
    
#     else:
#         try:
#             cart = Cart.objects.filter(cart_id = _cart_id(request))
#             cart_items = CartItem.objects.all.filter(cart = cart[:1])
#             for cart_item in cart_items:
#                 cart_count+=cart_item.quantity

#         except Cart.DoesNotExist:
#             cart_count = 0

#     return dict(cart_count=cart_count)

from .models import Cart, CartItem
from .views import _cart_id

def counter(request):
    cart_count = 0
    if 'admin' in request.path:
        return {}  # Don't calculate cart count for admin paths
    else:
        try:
            # Retrieve the cart for the current session
            # cart = Cart.objects.filter(cart_id=_cart_id(request)).first()
            # print("cart", cart, "iiif")
            # if cart:
                # Retrieve all items associated with this cart
            cart = Cart.objects.filter(cart_id=_cart_id(request)).first()   
            if request.user.is_authenticated:
                cart_items = CartItem.objects.filter(user = request.user)
            
            else:
                
                cart_items = CartItem.objects.filter(cart=cart)

            for cart_item in cart_items:
                cart_count += cart_item.quantity  
        except Cart.DoesNotExist:
            cart_count = 0  # Handle case where cart does not exist

    # Return the cart count as a dictionary to be used in templates
    print("carrrt",cart_count)
    return dict(cart_count=cart_count)


