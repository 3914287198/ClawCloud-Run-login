#!/usr/bin/env python3
"""
GitHub 账号 ClawCloud 保活脚本
- 极简方案，专注保活，避免复杂交互
- 自动刷新会话，防止账号失效
- 仅推送关键验证链接到钉钉
"""

import os
import sys
import time
import json
import requests
from playwright.sync_api import sync_playwright
from datetime import datetime

# ==================== 核心配置 ====================
# 基础配置
CLAW_CLOUD_URL = "https://eu-central-1.run.claw.cloud"
GITHUB_LOGIN_URL = "https://github.com/login"
# 保活等待时间（秒）
VERIFY_WAIT_TIME = 60
# 钉钉配置（仅推送验证链接）
DINGTALK_ACCESS_TOKEN = 'ada335c55c006ddc351eaad285a0d1d6d45e8e0a7a917170909edba0405eb34e'
DINGTALK_SECRET = 'SECe15f72fe6b681f05e537fc413fdb42e6f5da3571cdf4bca3c79c3a4e841398e4'

# 环境变量（必填）
GH_USERNAME = os.environ.get('GH_USERNAME')
GH_PASSWORD = os.environ.get('GH_PASSWORD')
GH_SESSION = os.environ.get('GH_SESSION', '')

# 全局状态
global_context = None
dingtalk_ok = False


# ==================== 工具函数 ====================
def print_flush(msg, level="INFO"):
    """实时打印日志，避免堆积"""
    icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️"}
    log_line = f"{datetime.now().strftime('%Y-%m-%d %H:%M:%S')} {icons.get(level)} {msg}"
    print(log_line)
    sys.stdout.flush()
    return log_line


def send_dingtalk_link(link):
    """仅推送纯链接到钉钉"""
    try:
        import hmac
        import hashlib
        import base64
        import urllib.parse
        
        timestamp = int(round(time.time() * 1000))
        string_to_sign = f'{timestamp}\n{DINGTALK_SECRET}'
        hmac_code = hmac.new(DINGTALK_SECRET.encode('utf-8'), 
                            string_to_sign.encode('utf-8'), 
                            digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        
        url = f'https://oapi.dingtalk.com/robot/send?access_token={DINGTALK_ACCESS_TOKEN}&timestamp={timestamp}&sign={sign}'
        headers = {'Content-Type': 'application/json;charset=utf-8'}
        data = {
            "msgtype": "text",
            "text": {"content": link},
            "at": {"isAtAll": False}
        }
        
        resp = requests.post(url, headers=headers, json=data, timeout=10)
        if resp.status_code == 200 and resp.json().get('errcode') == 0:
            print_flush("钉钉链接推送成功", "SUCCESS")
        else:
            print_flush(f"钉钉推送失败: {resp.text}", "ERROR")
    except Exception as e:
        print_flush(f"钉钉推送异常: {str(e)}", "ERROR")


def update_github_secret(new_session):
    """更新 GitHub Secret 中的 GH_SESSION"""
    try:
        REPO_TOKEN = os.environ.get('REPO_TOKEN')
        REPO = os.environ.get('GITHUB_REPOSITORY')
        if not REPO_TOKEN or not REPO:
            print_flush("缺少 REPO_TOKEN，跳过 Secret 更新", "WARN")
            return
        
        from nacl import encoding, public
        headers = {"Authorization": f"token {REPO_TOKEN}", "Accept": "application/vnd.github.v3+json"}
        
        # 获取公钥
        pk_resp = requests.get(f"https://api.github.com/repos/{REPO}/actions/secrets/public-key", 
                              headers=headers, timeout=30)
        if pk_resp.status_code != 200:
            print_flush("获取公钥失败", "ERROR")
            return
        
        pk_data = pk_resp.json()
        public_key = public.PublicKey(pk_data['key'].encode(), encoding.Base64Encoder())
        encrypted_value = public.SealedBox(public_key).encrypt(new_session.encode())
        
        # 更新 Secret
        update_resp = requests.put(
            f"https://api.github.com/repos/{REPO}/actions/secrets/GH_SESSION",
            headers=headers,
            json={
                "encrypted_value": base64.b64encode(encrypted_value).decode(),
                "key_id": pk_data['key_id']
            },
            timeout=30
        )
        
        if update_resp.status_code in [201, 204]:
            print_flush("GH_SESSION 更新成功", "SUCCESS")
        else:
            print_flush(f"更新 Secret 失败: {update_resp.status_code}", "ERROR")
    except Exception as e:
        print_flush(f"更新 Secret 异常: {str(e)}", "ERROR")


# ==================== 核心保活逻辑 ====================
def init_browser_context():
    """初始化浏览器上下文，模拟真实环境"""
    global global_context
    try:
        playwright = sync_playwright().start()
        browser = playwright.chromium.launch(
            headless=True,
            args=[
                '--no-sandbox',
                '--disable-blink-features=AutomationControlled',
                '--disable-dev-shm-usage',
                '--disable-web-security',
                '--ignore-certificate-errors',
                '--disable-extensions'
            ]
        )
        
        # 模拟真实浏览器指纹
        global_context = browser.new_context(
            viewport={'width': 1920, 'height': 1080},
            user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
            locale='en-US',
            timezone_id='Europe/Berlin',
            extra_http_headers={
                'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
                'Accept-Language': 'en-US,en;q=0.9',
                'Referer': 'https://github.com/',
                'Sec-Fetch-Dest': 'document',
                'Sec-Fetch-Mode': 'navigate',
                'Sec-Fetch-Site': 'same-origin',
                'Upgrade-Insecure-Requests': '1'
            }
        )
        
        # 禁用自动化检测
        global_context.add_init_script("""
            Object.defineProperty(navigator, 'webdriver', {get: () => undefined});
            Object.defineProperty(navigator, 'languages', {get: () => ['en-US', 'en']});
            Object.defineProperty(navigator, 'plugins', {get: () => [1, 2, 3]});
        """)
        
        print_flush("浏览器上下文初始化成功", "SUCCESS")
        return browser, global_context
    except Exception as e:
        print_flush(f"浏览器初始化失败: {str(e)}", "ERROR")
        sys.exit(1)


def load_github_cookies(page):
    """加载已有的 GitHub Session Cookie"""
    if not GH_SESSION:
        print_flush("无 GH_SESSION，跳过 Cookie 加载", "WARN")
        return False
    
    try:
        cookies = [
            {"name": "user_session", "value": GH_SESSION, "domain": ".github.com", "path": "/"},
            {"name": "logged_in", "value": "yes", "domain": ".github.com", "path": "/"},
            {"name": "dotcom_user", "value": GH_USERNAME, "domain": ".github.com", "path": "/"}
        ]
        global_context.add_cookies(cookies)
        page.reload(timeout=10000)
        print_flush("GitHub Cookie 加载成功", "SUCCESS")
        return True
    except Exception as e:
        print_flush(f"加载 Cookie 失败: {str(e)}", "ERROR")
        return False


def github_login(page):
    """极简 GitHub 登录流程，仅处理核心步骤"""
    try:
        # 等待登录页面加载
        page.wait_for_selector('input#login_field', timeout=10000)
        print_flush("开始 GitHub 登录", "INFO")
        
        # 填写账号密码
        page.fill('input#login_field', GH_USERNAME)
        page.fill('input#password', GH_PASSWORD)
        page.click('input[name="commit"]')
        page.wait_for_load_state('networkidle', timeout=20000)
        
        current_url = page.url
        print_flush(f"登录后跳转至: {current_url}", "INFO")
        
        # 处理设备验证
        if 'verified-device' in current_url or 'device-verification' in current_url:
            print_flush("触发设备验证，推送链接到钉钉", "WARN")
            send_dingtalk_link(current_url)
            
            # 等待验证（延长时间）
            for i in range(VERIFY_WAIT_TIME):
                time.sleep(1)
                new_url = page.url
                if 'verified-device' not in new_url and 'device-verification' not in new_url:
                    print_flush("设备验证通过，继续流程", "SUCCESS")
                    break
                if i % 10 == 0:
                    print_flush(f"等待验证... ({i}/{VERIFY_WAIT_TIME}秒)")
            else:
                print_flush("设备验证超时", "ERROR")
                return False
        
        # 检查登录状态
        if 'github.com/settings/profile' in page.url or 'github.com/dashboard' in page.url:
            print_flush("GitHub 登录成功", "SUCCESS")
            return True
        
        # 提取新的 Session Cookie
        new_session = None
        for cookie in global_context.cookies():
            if cookie['name'] == 'user_session' and '.github.com' in cookie['domain']:
                new_session = cookie['value']
                break
        
        if new_session and new_session != GH_SESSION:
            print_flush(f"获取到新 Session: {new_session[:10]}...", "SUCCESS")
            update_github_secret(new_session)
        
        return True
    except Exception as e:
        print_flush(f"GitHub 登录失败: {str(e)}", "ERROR")
        return False


def clawcloud_keepalive():
    """核心保活逻辑：访问 ClawCloud 并维持会话"""
    browser, context = init_browser_context()
    page = context.new_page()
    
    try:
        # 步骤1：访问 ClawCloud 登录页
        print_flush("访问 ClawCloud 登录页", "INFO")
        page.goto(f"{CLAW_CLOUD_URL}/signin", timeout=30000)
        page.wait_for_load_state('networkidle', timeout=20000)
        
        # 检查是否已登录
        if 'signin' not in page.url.lower():
            print_flush("ClawCloud 已登录，直接保活", "SUCCESS")
            # 访问核心页面保活
            page.goto(f"{CLAW_CLOUD_URL}/apps", timeout=30000)
            page.wait_for_load_state('networkidle', timeout=10000)
            print_flush("ClawCloud 保活完成", "SUCCESS")
            return True
        
        # 步骤2：点击 GitHub 登录按钮
        print_flush("点击 GitHub 登录按钮", "INFO")
        github_btn_selector = [
            'button:has-text("GitHub")',
            'a[href*="github"]',
            '//*[contains(text(), "Sign in with GitHub")]'
        ]
        
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
            return False
        
        # 步骤3：处理 GitHub 授权流程
        page.wait_for_load_state('networkidle', timeout=20000)
        current_url = page.url
        
        # 加载已有 Cookie
        load_github_cookies(page)
        
        # 需要重新登录
        if 'github.com/login' in current_url:
            if not github_login(page):
                return False
        
        # 步骤4：授权 ClawCloud 访问
        if 'github.com/login/oauth/authorize' in current_url:
            print_flush("GitHub 授权页面，点击授权", "INFO")
            page.wait_for_selector('button[name="authorize"]', timeout=10000)
            page.click('button[name="authorize"]')
            page.wait_for_load_state('networkidle', timeout=20000)
        
        # 步骤5：验证 ClawCloud 登录状态
        if 'claw.cloud' in page.url and 'signin' not in page.url.lower():
            print_flush("ClawCloud 登录成功，开始保活", "SUCCESS")
            # 访问多个页面确保会话有效
            for path in ['/', '/apps', '/settings']:
                try:
                    page.goto(f"{CLAW_CLOUD_URL}{path}", timeout=20000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                    print_flush(f"访问 {path} 成功", "SUCCESS")
                except:
                    print_flush(f"访问 {path} 失败，跳过", "WARN")
            return True
        
        print_flush("ClawCloud 登录流程未完成", "ERROR")
        return False
    
    except Exception as e:
        print_flush(f"保活流程异常: {str(e)}", "ERROR")
        return False
    finally:
        browser.close()


# ==================== 主函数 ====================
if __name__ == "__main__":
    print_flush("=== GitHub ClawCloud 保活脚本启动 ===", "INFO")
    
    # 检查必填参数
    if not GH_USERNAME or not GH_PASSWORD:
        print_flush("缺少 GH_USERNAME 或 GH_PASSWORD 环境变量", "ERROR")
        sys.exit(1)
    
    # 执行保活
    success = clawcloud_keepalive()
    
    if success:
        print_flush("=== 保活流程执行成功 ===", "SUCCESS")
        sys.exit(0)
    else:
        print_flush("=== 保活流程执行失败 ===", "ERROR")
        sys.exit(1)
