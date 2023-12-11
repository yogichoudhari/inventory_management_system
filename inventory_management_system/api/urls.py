from django.urls import path
from . import views
urlpatterns = [
    path('product/',views.product,name='product'),
    path('product/<int:id>',views.product,name='product'),
    path('register/', views.register,name='register'),
    path('login/',views.login,name='login'),
    path('update-stock/',views.update_stock,name="update_stock"),
    path("update-user-profile/",views.update_user_profile,name="update_user_profile"),
    path("check-product/",views.check_product,name="check_product"),
    path("product/<int:id>/make-purchase",views.make_purchase,name="make_purchase"),
    path("add-product/",views.add_product,name="add_product"),
    path("users/",views.users,name="users"),
    path("grant-permission/", views.grant_permission_to_user),
    path("create-permission-set/", views.create_permission_set),
    path("payment-success/<str:session_id>",views.payment_success),
    path("payment-failed/<str:session_id>",views.payment_failed),
    path("payment-history/",views.payment_history)
]



