from django.shortcuts import render, get_object_or_404
from . models import Product
from category.models import Category
from cart.models import CartItem, Cart
from cart.views import _cart_id
from django.http import HttpResponse
from django.core.paginator import EmptyPage, PageNotAnInteger, Paginator
from django.db.models import Q
# Create your views here.
def store(request,category_slug = None):
    categories = None
    products = None

    if category_slug!=None:
        categories = get_object_or_404(Category, slug= category_slug)
        product = Product.objects.all().filter(category = categories, is_available = True )
        paginator= Paginator(product,2)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
        product_count = len(product)
    else:
        product = Product.objects.all().filter(is_available = True).order_by('id')
        paginator= Paginator(product,2)
        page = request.GET.get('page')
        paged_products = paginator.get_page(page)
        product_count = len(product)

    context = {
        'products':paged_products, 
        'product_count':product_count,
    }

    return render(request, 'store/store.html',context)

def product_detail(request, category_slug, product_slug):
    try:
        single_product = Product.objects.get(category__slug=category_slug, slug=product_slug)
        is_out_of_stock = single_product.stock <= 0
        is_cart = CartItem.objects.filter(cart__cart_id = _cart_id(request), product = single_product).exists()
        
    except Exception as e:
        raise e

    context = {
        'single_product': single_product,
        'is_out_of_stock':is_out_of_stock,
        'is_cart':is_cart,
    }
    return render(request, 'store/product_detail.html', context)

def search(request):
    if 'keyword' in request.GET:
        keyword = request.GET['keyword']

    if keyword:
        products = Product.objects.order_by('-created_date').filter(Q(description__icontains = keyword) | Q(product_name__icontains = keyword ))
        product_count = len(products)
    context = {
        'products':products,
        'product_count' : product_count
    }
    return render(request, 'store/store.html',context)
