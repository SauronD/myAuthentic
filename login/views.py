from django.shortcuts import render, redirect
from django.http import HttpResponse, JsonResponse
from django.contrib import messages
from login.models import Account
import time
import hashlib
import base64
# Create your views here.


# 用于存储已使用的 nonce 及其时间戳
used_nonces = {}
def hash_data(data):
    """对输入数据进行 SHA-256 哈希，返回 Base64 编码字符串"""
    sha256_hash = hashlib.sha256(data.encode()).digest()
    return base64.b64encode(sha256_hash).decode()
def login(request):
    # admin 123456
    # admin2 123456789
    # llw 123
    client_ip = request.META['REMOTE_ADDR']
    print(f"Client_ip:{client_ip}")
    if request.method == 'POST':
        # 获取表单中的字段
        username = request.POST.get('username')
        received_hashed_password = request.POST.get('hashed_password')
        timestamp = request.POST.get('timestamp')
        nonce = request.POST.get('nonce')

        # 后端调试输出
        print(f"Username: {username}")
        print(f"Received Hashed Password: {received_hashed_password}")
        print(f"Timestamp (ms): {timestamp}")
        print(f"Nonce: {nonce}")

        # 数据库读取
        user = Account.objects.get(username=username)
        original_password_hash = user.hashed_password
        # 假设的固定用户名和原始密码的哈希值（例如 SHA-256 哈希后的 "123456"）
        stored_username = user.username
        print(f"Datasets Username: {stored_username}")
        print(f"Datasets Password: {original_password_hash}")
        # stored_username = "admin"
        # original_password = "123456789"
        #original_password_hash = hash_data(original_password)

        # 转换时间戳为秒级并验证其有效范围
        try:
            current_time = int(time.time())
            valid_timestamp = int(timestamp) // 1000  # 将毫秒级转换为秒级
            print(f"Converted Timestamp (s): {valid_timestamp}")
            print(f"Received Timestamp (s): {timestamp}")

            if abs(current_time - valid_timestamp) > 60:
                return HttpResponse("Timestamp invalid or request expired")

        except ValueError:
            return HttpResponse("Invalid timestamp")

        # 验证 nonce 是否已使用
        if nonce in used_nonces:
            return HttpResponse("Replay attack detected")
        # 生成后端期望的哈希值，并与接收到的哈希密码进行对比
        # 组合哈希后的密码、用户名、时间戳和随机数
        data_to_hash = original_password_hash + username + str(timestamp) + nonce
        expected_hashed_password = hash_data(data_to_hash)
        print(f"Expected Hashed Password: {expected_hashed_password}")

        # 比较接收到的哈希值和后端生成的哈希值
        if username == stored_username and received_hashed_password == expected_hashed_password:
            # 将该 nonce 存入字典并在 60 秒后清理
            used_nonces[nonce] = valid_timestamp
            for nonce, timestamp in used_nonces.items():
                print(f"Nonce: {nonce}, Timestamp: {timestamp}")
            # 清理过期的 nonces
            for stored_nonce in list(used_nonces):
                if current_time - used_nonces[stored_nonce] > 60:
                    del used_nonces[stored_nonce]

            return HttpResponse("Login successful")
            # response_data = {
            #     "message": "Login successful",
            #     "username": stored_username,
            #     "timestamp": timestamp,
            #     "nonce": nonce
            # }
            # return JsonResponse(response_data, status=200)

        else:
            # return HttpResponse("Invalid username or password")
            messages.error(request, "Invalid username or password")
            return redirect('login:login')
            # return JsonResponse({"message": "Invalid username or password"}, status=400)

    return render(request, 'login.html')


def register(request):
    if request.method == "POST":
        # 获取表单中的字段
        username = request.POST.get('username')
        received_hashed_password = request.POST.get('hashed_password')

        # 后端调试输出
        print(f"Username: {username}")
        print(f"Received Hashed Password: {received_hashed_password}")

        # 检查用户名是否已存在
        if Account.objects.filter(username=username).exists():
            return JsonResponse({"message": "Username already exists"}, status=400)

        Account.objects.create(username=username, hashed_password=received_hashed_password)

        return JsonResponse({"message": "Registration successful"},status=200)

    return render(request, 'register.html')

def success(request):
    return render(request, 'success.html')