from django.urls import path
from . import views
urlpatterns = [
    path('product/',views.product,name='product'),
    path('product/<int:id>',views.product,name='product'),
    path('register/', views.register,name='register'),
    path('login/',views.login,name='login'),
    path('update_stock/',views.update_stock,name="update_stock"),
    path("update_user_profile/",views.update_user_profile,name="update_user_profile"),
    path("check_product/",views.check_product,name="check_product"),
    path("product/<int:id>/make_purchase",views.make_purchase,name="make_purchase"),
    path("add_product/",views.add_product,name="add_product"),
    path("users/",views.users,name="users"),
]

