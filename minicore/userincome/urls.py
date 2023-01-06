from django.urls import path
from . import views
from django.views.decorators.csrf import csrf_exempt

urlpatterns = [
    path('', views.inicio, name="income"),
    path('add-income', views.add_income, name="add-income"),
    path('edit-income/<int:id>', views.income_edit, name="income-edit"),
    path('income-delete/<int:id>', views.delete_income, name="income-delete"),
    path('search-income', csrf_exempt(views.search_income), name="search_income"),
    path('expense_category_summary', views.expense_category_summary, name="expense_category_summary"),
    path('stats-income', views.stats_view, name="stats-income"),
    path('export_csv', views.export_csv, name="export-csv"),
]
