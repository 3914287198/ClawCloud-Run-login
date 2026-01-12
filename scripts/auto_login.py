#!/usr/bin/env python3
"""
ClawCloud GitHub 保活脚本
- 严格匹配你的流程：Cookie加载→登录→验证→授权→保活→更新Cookie
- 修复钉钉通知错误代码
"""

import os
import sys
import time
import json
import requests
import hmac
import hashlib
import base64
import urllib.parse
from playwright.sync_api import sync_playwright
from datetime import datetime

# ==================== 配置 ====================
CLAW_CLOUD_URL = "https://eu-central-1.run.claw.cloud"
SIGNIN_URL = f"{CLAW_CLOUD_URL}/signin"
DEVICE_VERIFY_WAIT = 30  # 按你要求设置30秒
# 钉钉配置（修复错误代码）
DINGTALK_ACCESS_TOKEN = 'ada335c55c006ddc351eaad285a0d1d6d45e8e0a7a917170909edba0405eb34e'
DINGTALK_SECRET = 'SECe15f72fe6b681f05e537fc413fdb42e6f5da3571cdf4bca3c79c3a4e841398e4'

# 环境变量
GH_USERNAME = os.environ.get('GH_USERNAME')
GH_PASSWORD = os.environ.get('GH_PASSWORD')
GH_SESSION = os.environ.get('GH_SESSION', '').strip()
REPO_TOKEN = os.environ.get('REPO_TOKEN')
GITHUB_REPOSITORY = os.environ.get('GITHUB_REPOSITORY')


# ==================== 工具函数 ====================
def print_flush(msg, level="INFO"):
    """实时打印流程日志"""
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
    log_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {icons.get(level)} {msg}"
    print(log_line)
    sys.stdout.flush()
    return log_line


def send_dingtalk_msg(content, is_verify=False):
    """修复钉钉错误代码的消息发送函数"""
    try:
        timestamp = int(round(time.time() * 1000))
        # 生成签名（修复编码问题）
        string_to_sign = f"{timestamp}\n{DINGTALK_SECRET}".encode('utf-8')
        hmac_code = hmac.new(DINGTALK_SECRET.encode('utf-8'), string_to_sign, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        
        url = f"https://oapi.dingtalk.com/robot/send?access_token={DINGTALK_ACCESS_TOKEN}&timestamp={timestamp}&sign={sign}"
        headers = {"Content-Type": "application/json;charset=utf-8"}
        
        # 验证消息专用格式
        if is_verify:
            content = f"""⚠️ GitHub 设备验证需要你手动完成
操作方式（二选一）：
1. 检查 GitHub 绑定邮箱，点击邮件中的验证链接
2. 打开 GitHub App 批准设备登录
⏰ 请在 {DEVICE_VERIFY_WAIT} 秒内完成验证"""
        
        data = {
            "msgtype": "text",
            "text": {"content": content},
            "at": {"isAtAll": False}
        }
        
        # 修复请求格式（使用json.dumps确保编码）
        response = requests.post(
            url,
            headers=headers,
            data=json.dumps(data, ensure_ascii=False).encode('utf-8'),
            timeout=15
        )
        response.raise_for_status()
        result = response.json()
        if result.get('errcode') == 0:
            print_flush("钉钉消息发送成功", "SUCCESS")
        else:
            print_flush(f"钉钉消息发送失败: {result.get('errmsg')}", "ERROR")
    except Exception as e:
        print_flush(f"钉钉消息发送异常: {str(e)}", "ERROR")


def update_gh_session_secret(new_session):
    """更新 GitHub Secret 中的 GH_SESSION"""
    if not REPO_TOKEN or not GITHUB_REPOSITORY:
        print_flush("缺少 REPO_TOKEN 或仓库信息，跳过 Secret 更新", "WARN")
        return
    
    try:
        from nacl import encoding, public
        # 获取公钥
        headers = {"Authorization": f"token {REPO_TOKEN}", "Accept": "application/vnd.github.v3+json"}
        pubkey_resp = requests.get(
            f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/secrets/public-key",
            headers=headers,
            timeout=30
        )
        pubkey_resp.raise_for_status()
        pubkey_data = pubkey_resp.json()
        
        # 加密Session
        public_key = public.PublicKey(pubkey_data['key'].encode(), encoding.Base64Encoder())
        encrypted_session = public.SealedBox(public_key).encrypt(new_session.encode())
        
        # 更新Secret
        update_resp = requests.put(
            f"https://api.github.com/repos/{GITHUB_REPOSITORY}/actions/secrets/GH_SESSION",
            headers=headers,
            json={
                "encrypted_value": base64.b64encode(encrypted_session).decode(),
                "key_id": pubkey_data['key_id']
            },
            timeout=30
        )
        update_resp.raise_for_status()
        print_flush("GH_SESSION Secret 更新成功", "SUCCESS")
    except Exception as e:
        print_flush(f"更新 GH_SESSION Secret 失败: {str(e)}", "ERROR")


# ==================== 核心流程函数 ====================
def run_flow():
    print_flush("=== 开始 ClawCloud GitHub 保活流程 ===", "INFO")
    browser = None
    context = None
    
    try:
        # 初始化Playwright
        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(
            headless=True,
            args=['--no-sandbox', '--disable-blink-features=AutomationControlled']
        )
        context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/121.0.0.0 Safari/537.36'
        )
        page = context.new_page()
        print_flush("浏览器上下文初始化完成", "SUCCESS")


        # 步骤1：加载已保存的Cookie（如果有）
        print_flush("加载已保存的 Cookie（如果有）", "STEP")
        if GH_SESSION:
            try:
                context.add_cookies([
                    {"name": "user_session", "value": GH_SESSION, "domain": ".github.com", "path": "/"},
                    {"name": "logged_in", "value": "yes", "domain": ".github.com", "path": "/"}
                ])
                print_flush("已加载保存的 GH_SESSION Cookie", "SUCCESS")
            except Exception as e:
                print_flush(f"加载Cookie失败: {str(e)}", "WARN")


        # 步骤2：访问 ClawCloud
        print_flush("访问 ClawCloud", "STEP")
        page.goto(SIGNIN_URL, timeout=30000)
        page.wait_for_load_state('networkidle', timeout=20000)


        # 步骤3：检查是否已登录
        print_flush("检查是否已登录", "STEP")
        if 'signin' not in page.url.lower():
            print_flush("已登录 ClawCloud，直接保活", "SUCCESS")
            
            # 保活：访问核心页面
            print_flush("保活：访问控制台、应用页面", "STEP")
            for path in ['/', '/apps']:
                page.goto(f"{CLAW_CLOUD_URL}{path}", timeout=20000)
                page.wait_for_load_state('networkidle', timeout=10000)
                print_flush(f"已访问 {path}", "SUCCESS")
            
            # 提取新Cookie
            print_flush("提取新的 Session Cookie", "STEP")
            new_session = None
            for cookie in context.cookies():
                if cookie['name'] == 'user_session' and '.github.com' in cookie['domain']:
                    new_session = cookie['value']
                    break
            if new_session and new_session != GH_SESSION:
                update_gh_session_secret(new_session)
            
            # 发送完成通知
            send_dingtalk_msg("✅ ClawCloud 保活完成（已登录状态）")
            print_flush("=== 保活流程完成 ✅ ===", "SUCCESS")
            return True


        # 步骤4：点击 GitHub 登录
        print_flush("点击 GitHub 登录", "STEP")
        github_btn_selector = ['button:has-text("GitHub")', 'a[href*="github"]', '//*[text()="Sign in with GitHub"]']
        btn_clicked = False
        for selector in github_btn_selector:
            try:
                page.wait_for_selector(selector, timeout=5000)
                page.click(selector)
                btn_clicked = True
                break
            except:
                continue
        if not btn_clicked:
            print_flush("未找到 GitHub 登录按钮", "ERROR")
            send_dingtalk_msg("❌ 保活失败：未找到 GitHub 登录按钮")
            return False
        page.wait_for_load_state('networkidle', timeout=20000)


        # 步骤5：检查Cookie是否有效
        print_flush("检查 Cookie 是否有效", "STEP")
        current_url = page.url
        if 'github.com/login/oauth/authorize' in current_url:
            print_flush("Cookie 有效，直接 OAuth 授权", "SUCCESS")
            
            # 执行OAuth授权
            print_flush("执行 OAuth 授权", "STEP")
            page.wait_for_selector('button[name="authorize"]', timeout=10000)
            page.click('button[name="authorize"]')
            page.wait_for_load_state('networkidle', timeout=20000)
            
            # 跳过重定向步骤，直接到保活
            goto_keepalive(page, context)
            return True


        # 步骤6：输入用户名密码
        print_flush("输入用户名密码", "STEP")
        try:
            page.wait_for_selector('input#login_field', timeout=10000)
            page.fill('input#login_field', GH_USERNAME)
            page.fill('input#password', GH_PASSWORD)
            page.click('input[name="commit"]')
            page.wait_for_load_state('networkidle', timeout=20000)
            print_flush("已输入用户名密码并提交", "SUCCESS")
        except Exception as e:
            print_flush(f"输入凭据失败: {str(e)}", "ERROR")
            send_dingtalk_msg(f"❌ 保活失败：输入凭据失败 - {str(e)}")
            return False


        # 步骤7：需要设备验证？
        print_flush("检查是否需要设备验证", "STEP")
        current_url = page.url
        if 'verified-device' in current_url or 'device-verification' in current_url:
            print_flush(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒", "WARN")
            send_dingtalk_msg("", is_verify=True)  # 发送验证通知
            
            # 等待验证
            verify_success = False
            for i in range(DEVICE_VERIFY_WAIT):
                time.sleep(1)
                if i % 5 == 0:
                    print_flush(f"等待验证... ({i}/{DEVICE_VERIFY_WAIT}秒)")
                # 检查验证状态
                new_url = page.url
                if 'verified-device' not in new_url and 'device-verification' not in new_url:
                    print_flush("设备验证通过", "SUCCESS")
                    verify_success = True
                    break
            if not verify_success:
                print_flush("设备验证超时", "ERROR")
                send_dingtalk_msg("❌ 保活失败：设备验证超时")
                return False


        # 步骤8：登录成功
        print_flush("GitHub 登录成功", "SUCCESS")


        # 步骤9：OAuth 授权
        print_flush("执行 OAuth 授权", "STEP")
        if 'github.com/login/oauth/authorize' in page.url:
            try:
                page.wait_for_selector('button[name="authorize"]', timeout=10000)
                page.click('button[name="authorize"]')
                page.wait_for_load_state('networkidle', timeout=20000)
                print_flush("OAuth 授权完成", "SUCCESS")
            except Exception as e:
                print_flush(f"OAuth 授权失败: {str(e)}", "ERROR")
                send_dingtalk_msg(f"❌ 保活失败：OAuth 授权失败 - {str(e)}")
                return False


        # 步骤10：重定向到 ClawCloud
        print_flush("等待重定向到 ClawCloud", "STEP")
        redirect_success = False
        for i in range(30):
            time.sleep(1)
            if 'claw.cloud' in page.url and 'signin' not in page.url.lower():
                print_flush("重定向到 ClawCloud 成功", "SUCCESS")
                redirect_success = True
                break
        if not redirect_success:
            print_flush("重定向超时", "ERROR")
            send_dingtalk_msg("❌ 保活失败：重定向到 ClawCloud 超时")
            return False


        # 步骤11：保活（访问控制台、应用页面）
        print_flush("保活：访问控制台、应用页面", "STEP")
        for path in ['/', '/apps']:
            page.goto(f"{CLAW_CLOUD_URL}{path}", timeout=20000)
            page.wait_for_load_state('networkidle', timeout=10000)
            print_flush(f"已访问 {path}", "SUCCESS")


        # 步骤12：提取新的 Session Cookie
        print_flush("提取新的 Session Cookie", "STEP")
        new_session = None
        for cookie in context.cookies():
            if cookie['name'] == 'user_session' and '.github.com' in cookie['domain']:
                new_session = cookie['value']
                break
        if new_session:
            print_flush(f"获取到新 Session: {new_session[:10]}...", "SUCCESS")
            # 步骤13：自动更新 GH_SESSION Secret
            update_gh_session_secret(new_session)
        else:
            print_flush("未获取到新 Session Cookie", "WARN")


        # 步骤14：发送钉钉通知
        send_dingtalk_msg("✅ ClawCloud GitHub 保活流程完成")


        print_flush("=== 保活流程完成 ✅ ===", "SUCCESS")
        return True

    except Exception as e:
        print_flush(f"流程异常: {str(e)}", "ERROR")
        send_dingtalk_msg(f"❌ 保活流程异常：{str(e)}")
        return False
    finally:
        if browser:
            browser.close()


def goto_keepalive(page, context):
    """保活子流程（复用）"""
    print_flush("保活：访问控制台、应用页面", "STEP")
    for path in ['/', '/apps']:
        page.goto(f"{CLAW_CLOUD_URL}{path}", timeout=20000)
        page.wait_for_load_state('networkidle', timeout=10000)
        print_flush(f"已访问 {path}", "SUCCESS")
    
    # 提取新Cookie
    print_flush("提取新的 Session Cookie", "STEP")
    new_session = None
    for cookie in context.cookies():
        if cookie['name'] == 'user_session' and '.github.com' in cookie['domain']:
            new_session = cookie['value']
            break
    if new_session and new_session != GH_SESSION:
        update_gh_session_secret(new_session)
    
    send_dingtalk_msg("✅ ClawCloud 保活完成（Cookie有效）")
    print_flush("=== 保活流程完成 ✅ ===", "SUCCESS")


# ==================== 主函数 ====================
if __name__ == "__main__":
    if not GH_USERNAME or not GH_PASSWORD:
        print_flush("缺少 GH_USERNAME 或 GH_PASSWORD 环境变量", "ERROR")
        sys.exit(1)
    success = run_flow()
    sys.exit(0 if success else 1)
