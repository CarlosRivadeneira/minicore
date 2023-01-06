from django.shortcuts import render, redirect
from django.contrib.auth.decorators import login_required
from .models import Category, Expense
from django.contrib import messages
from django.core.paginator import Paginator
import json
from django.http import JsonResponse, HttpResponse
import datetime
import csv

# Create your views here.

def search_expenses(request):
    if request.method=="POST":
        search_str=json.loads(request.body).get('searchText')

        expenses=Expense.objects.filter(
            amount__istartswith=search_str, owner=request.user) | Expense.objects.filter(
            date__istartswith=search_str, owner=request.user) | Expense.objects.filter(
            description__icontains=search_str, owner=request.user) | Expense.objects.filter(
            category__icontains=search_str, owner=request.user)

        data=expenses.values()

        return JsonResponse(list(data), safe=False)
        

@login_required(login_url='/authentication/login')
def inicio(request):
    categories = Category.objects.all()
    expenses = Expense.objects.filter(owner=request.user)
    paginator = Paginator(expenses, 5)
    page_number = request.GET.get('page')
    page_obj = Paginator.get_page(paginator, page_number)
    context = {
        'expenses': expenses,
        'page_obj': page_obj,
    }
    return render(request, 'GastApp/index.html', context)

@login_required(login_url='/authentication/login')
def add_expense(request):
    categories = Category.objects.all()
    context={
        'categories': categories,
        'values':request.POST
    }
    if request.method=="GET":
        return render(request, 'GastApp/add_expense.html', context)
    if request.method=="POST":
        amount=request.POST['amount']
        if not amount:
            messages.error(request, 'Se requiere el ingreso de una cantidad')
            return render(request, 'GastApp/add_expense.html', context)

        description=request.POST['description']

        date=request.POST['expense-date']
        if not date:
            messages.error(request, 'Se requiere la fecha en la que se realiza el gasto')
            return render(request, 'GastApp/add_expense.html', context)

        category=request.POST['category']

        if not description:
            messages.error(request, 'Se requiere la descripcion del gasto')
            return render(request, 'GastApp/add_expense.html', context)

        Expense.objects.create(owner=request.user, amount=amount, date=date, category=category, description=description)
        messages.success(request, 'El gasto ha sido guardado con exito')

        return redirect('GastApp')

@login_required(login_url='/authentication/login')
def expense_edit(request, id):
    expense=Expense.objects.get(pk=id)
    categories=Category.objects.all()
    context={
        'expense':expense,
        'values':expense,
        'categories':categories,
    }
    if request.method=="GET":
        return render(request, 'GastApp/edit-expense.html', context)
    if request.method=="POST":
        amount=request.POST['amount']
        if not amount:
            messages.error(request, 'Se requiere el ingreso de una cantidad')
            return render(request, 'GastApp/edit_expense.html', context)

        description=request.POST['description']

        date=request.POST['expense-date']
        if not date:
            messages.error(request, 'Se requiere la fecha en la que se realiza el gasto')
            return render(request, 'GastApp/edit_expense.html', context)

        category=request.POST['category']

        if not description:
            messages.error(request, 'Se requiere la descripcion del gasto')
            return render(request, 'GastApp/add_expense.html', context)

        expense.owner=request.user
        expense.amount=amount 
        expense.date=date
        expense.category=category
        expense.description=description
        expense.save()
        messages.success(request, 'El gasto ha sido actualizado con exito')

        return redirect('GastApp')

def delete_expense(request, id):
    expense=Expense.objects.get(pk=id)
    expense.delete()
    messages.success(request, 'El gasto se ha eliminado correctamente')
    return redirect('GastApp')

def expense_category_summary(request):
    todays_date=datetime.date.today()
    six_months_ago=todays_date-datetime.timedelta(days=30*6)
    expenses=Expense.objects.filter(owner=request.user,date__gte=six_months_ago,date__lte=todays_date)
    finalrep={}

    def get_category(expense):
        return expense.category

    category_list=list(set(map(get_category, expenses)))
    def get_expense_category_amount(category):
        amount=0
        filtered_by_category=expenses.filter(category=category)

        for item in filtered_by_category:
            amount+=item.amount

        return amount

    for x in expenses:
        for y in category_list:
            finalrep[y]=get_expense_category_amount(y)

    return JsonResponse({'expense_category_data':finalrep}, safe=False)

def stats_view(request):
    return render(request, 'GastApp/stats.html')

def export_csv(request):
    response=HttpResponse(content_type='text/csv')
    response['Content-Disposition']='attachment; filename=GastApp'+str(datetime.datetime.now())+'.csv'

    writer=csv.writer(response)
    writer.writerow(['Cantidad', 'Descripcion', 'Categoria', 'Fecha'])

    expenses=Expense.objects.filter(owner=request.user)

    for expense in expenses:
        writer.writerow([expense.amount, expense.description, expense.category, expense.date])
    
    return response