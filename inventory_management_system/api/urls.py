from django.urls import path
from . import views
urlpatterns = [
    path('product/',views.product),
    path('product/<int:id>',views.product),
    path('register/', views.register_admin),
    path('create-user/', views.create_user),
    path('verify/', views.verify),
    path('resend-otp/', views.resend_otp),
    path('login/',views.login,),
    path('update-stock/',views.update_stock),
    path("user-profile/",views.user_profile),
    path("check-product/<str:param>",views.check_product,),
    path("product/<int:id>/make-purchase",views.make_purchase),
    path("add-product/",views.add_product),
    path("users/",views.users),
    path("grant-permission/", views.grant_permission_to_user),
    path("create-permission-set/", views.create_permission_set),
    path("payment-success/<str:session_id>",views.payment_success),
    path("payment-failed/<str:session_id>",views.payment_failed),
    path("payment-history/",views.payment_history)
]



