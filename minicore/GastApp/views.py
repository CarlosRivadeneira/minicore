from django.shortcuts import render

# Create your views here.

def inicio(request):
    return render(request, 'GastApp/inicio.html')

def add_expense(request):
    return render(request, 'GastApp/add_expense.html')