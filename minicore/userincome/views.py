from django.shortcuts import render, redirect
from .models import Source, UserIncome
from django.core.paginator import Paginator
from django.contrib import messages
from django.contrib.auth.decorators import login_required
import json
from django.http import JsonResponse, HttpResponse
import datetime
import csv
# Create your views here.


def search_income(request):
    if request.method == 'POST':
        search_str = json.loads(request.body).get('searchText')
        income = UserIncome.objects.filter(
            amount__istartswith=search_str, owner=request.user) | UserIncome.objects.filter(
            date__istartswith=search_str, owner=request.user) | UserIncome.objects.filter(
            description__icontains=search_str, owner=request.user) | UserIncome.objects.filter(
            source__icontains=search_str, owner=request.user)
        data = income.values()
        return JsonResponse(list(data), safe=False)


@login_required(login_url='/authentication/login')
def inicio(request):
    categories = Source.objects.all()
    income = UserIncome.objects.filter(owner=request.user)
    paginator = Paginator(income, 5)
    page_number = request.GET.get('page')
    page_obj = Paginator.get_page(paginator, page_number)
    context = {
        'income': income,
        'page_obj': page_obj
    }
    return render(request, 'income/index.html', context)


@login_required(login_url='/authentication/login')
def add_income(request):
    sources = Source.objects.all()
    context = {
        'sources': sources,
        'values': request.POST
    }
    if request.method == 'GET':
        return render(request, 'income/add_income.html', context)

    if request.method == 'POST':
        amount = request.POST['amount']

        if not amount:
            messages.error(request, 'Se requiere una cantidad')
            return render(request, 'income/add_income.html', context)
        description = request.POST['description']
        date = request.POST['income-date']
        source = request.POST['source']

        if not description:
            messages.error(request, 'Se requiere una descripcion')
            return render(request, 'income/add_income.html', context)

        UserIncome.objects.create(owner=request.user, amount=amount, date=date,
                                  source=source, description=description)
        messages.success(request, 'La ganancia ha sido guardada con exito')

        return redirect('income')


@login_required(login_url='/authentication/login')
def income_edit(request, id):
    income = UserIncome.objects.get(pk=id)
    sources = Source.objects.all()
    context = {
        'income': income,
        'values': income,
        'sources': sources
    }
    if request.method == 'GET':
        return render(request, 'income/edit_income.html', context)
    if request.method == 'POST':
        amount = request.POST['amount']

        if not amount:
            messages.error(request, 'Se requiere una cantidad')
            return render(request, 'income/edit_income.html', context)
        description = request.POST['description']
        date = request.POST['income-date']
        source = request.POST['source']

        if not description:
            messages.error(request, 'Se requiere una descripcion')
            return render(request, 'income/edit_income.html', context)
        income.amount = amount
        income. date = date
        income.source = source
        income.description = description

        income.save()
        messages.success(request, 'La ganancia ha sido guardada de manera exitosa')

        return redirect('income')


def delete_income(request, id):
    income = UserIncome.objects.get(pk=id)
    income.delete()
    messages.success(request, 'La ganancia ha sido borrada')
    return redirect('income')

def expense_category_summary(request):
    todays_date=datetime.date.today()
    six_months_ago=todays_date-datetime.timedelta(days=30*6)
    incomes=UserIncome.objects.filter(owner=request.user,date__gte=six_months_ago,date__lte=todays_date)
    finalrep={}

    def get_category(income):
        return income.source

    category_list=list(set(map(get_category, incomes)))
    def get_expense_category_amount(source):
        amount=0
        filtered_by_category=incomes.filter(source=source)

        for item in filtered_by_category:
            amount+=item.amount

        return amount

    for x in incomes:
        for y in category_list:
            finalrep[y]=get_expense_category_amount(y)

    return JsonResponse({'expense_category_data':finalrep}, safe=False)

def stats_view(request):
    return render(request, 'Income/stats-income.html')

def export_csv(request):
    response=HttpResponse(content_type='text/csv')
    response['Content-Disposition']='attachment; filename=GastApp'+str(datetime.datetime.now())+'.csv'

    writer=csv.writer(response)
    writer.writerow(['Cantidad', 'Descripcion', 'Fuente', 'Fecha'])

    expenses=UserIncome.objects.filter(owner=request.user)

    for expense in expenses:
        writer.writerow([expense.amount, expense.description, expense.source, expense.date])
    
    return response