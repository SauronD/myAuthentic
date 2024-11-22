from django.shortcuts import render
from django.http import HttpResponse
# Create your views here.


def login(request):
    client_ip = request.META['REMOTE_ADDR']
    print(f"Client_ip:{client_ip}")
    if request.method == 'POST':
        # 获取用户输入的用户名和密码
        username = request.POST.get('username')
        password = request.POST.get('password')
        hashedPassword = request.POST.get('hashed_password')
        # 在后端显示用户名和密码，仅用于调试
        print(f"Username: {username}")
        print(f"Password: {password}")
        print(f"HashedPassword: {hashedPassword}")


        # 使用Django的认证系统验证用户
        #user = authenticate(request, username=username, password=password)
        # 时间戳+nonce(60s内唯一数验证)
        if password == "jZae727K08KaOmKSgOaGzww/XVqGr/PKEgIMkjrcbJI=":
            # 用户验证成功，执行登录操作
            return HttpResponse("Login successful")
        else:
            # 用户验证失败
            return HttpResponse("Invalid username or password")
    return render(request, 'login.html')

