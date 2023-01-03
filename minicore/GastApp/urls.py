from django.urls import path
from . import views

urlpatterns = [
    path('', views.inicio, name="GastApp"),
    path('add-expense', views.add_expense, name="add-expenses")
]
