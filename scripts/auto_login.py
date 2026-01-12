#!/usr/bin/env python3
"""
ClawCloud 自动登录脚本
- 仅推送验证链接到钉钉
- 修复 unknown provider 错误
"""

import os
import sys
import time
import base64
import requests
import hmac
import hashlib
import urllib.parse
import json
from datetime import datetime
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
CLAW_CLOUD_URL = "https://eu-central-1.run.claw.cloud"
SIGNIN_URL = f"{CLAW_CLOUD_URL}/signin"
DEVICE_VERIFY_WAIT = 60  # 延长等待时间到60秒，有足够时间操作

# 钉钉配置（仅保留链接推送）
DINGTALK_ACCESS_TOKEN = 'ada335c55c006ddc351eaad285a0d1d6d45e8e0a7a917170909edba0405eb34e'
DINGTALK_SECRET = 'SECe15f72fe6b681f05e537fc413fdb42e6f5da3571cdf4bca3c79c3a4e841398e4'


class DingTalk:
    """仅推送验证链接到钉钉"""
    
    def __init__(self):
        self.access_token = DINGTALK_ACCESS_TOKEN
        self.secret = DINGTALK_SECRET
        self.ok = bool(self.access_token and self.secret)
    
    def generate_sign(self, timestamp):
        string_to_sign = f'{timestamp}\n{self.secret}'
        hmac_code = hmac.new(self.secret.encode('utf-8'), string_to_sign.encode('utf-8'), digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return sign
    
    def send_verify_link(self, url):
        """仅发送验证链接，无多余内容"""
        if not self.ok:
            return
        
        try:
            timestamp = int(round(time.time() * 1000))
            sign = self.generate_sign(timestamp)
            
            url_api = f'https://oapi.dingtalk.com/robot/send?access_token={self.access_token}&timestamp={timestamp}&sign={sign}'
            headers = {'Content-Type': 'application/json;charset=utf-8'}
            
            # 仅包含纯链接，无其他文案
            data = {
                "msgtype": "text",
                "text": {"content": url},
                "at": {"isAtAll": False}
            }
            
            response = requests.post(
                url_api, 
                headers=headers, 
                data=json.dumps(data, ensure_ascii=False), 
                timeout=10
            )
        except Exception as e:
            print(f"❌ 钉钉链接推送失败: {e}")


class SecretUpdater:
    """GitHub Secret 更新器"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            self._print_flush("✅ Secret 自动更新已启用")
        else:
            self._print_flush("⚠️ Secret 自动更新未启用")
    
    def _print_flush(self, msg):
        print(msg)
        sys.stdout.flush()
    
    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public
            
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                return False
            
            key_data = r.json()
            pk = public.PublicKey(key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())
            
            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={"encrypted_value": base64.b64encode(encrypted).decode(), "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            self._print_flush(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    """自动登录（修复 unknown provider 错误）"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.dingtalk = DingTalk()
        self.secret = SecretUpdater()
        self.shots = []
        self.n = 0
        
    def log(self, msg, level="INFO"):
        """实时日志输出"""
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        sys.stdout.flush()
    
    def shot(self, page, name):
        self.n += 1
        f = f"{self.n:02d}_{name}.png"
        try:
            page.screenshot(path=f)
            self.shots.append(f)
        except:
            pass
        return f
    
    def click(self, page, sels, desc=""):
        for s in sels:
            try:
                el = page.locator(s).first
                if el.is_visible(timeout=5000):  # 延长点击等待时间
                    el.click()
                    self.log(f"已点击: {desc}", "SUCCESS")
                    return True
            except:
                pass
        return False
    
    def get_session(self, context):
        """提取 Session Cookie"""
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github.com' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None
    
    def save_cookie(self, value):
        """保存新 Cookie"""
        if not value:
            return
        
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
        else:
            self.log("已记录新 Cookie，需手动更新", "WARN")
    
    def wait_device(self, page):
        """等待设备验证（仅推送链接）"""
        verify_url = page.url
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        
        # 仅推送纯链接到钉钉，无其他内容
        self.dingtalk.send_verify_link(verify_url)
        
        # 优化等待逻辑：不主动刷新页面，避免破坏验证流程
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 10 == 0:
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒)")
            
            # 检查验证状态（仅读取URL，不刷新）
            current_url = page.url
            if 'verified-device' not in current_url and 'device-verification' not in current_url:
                self.log("设备验证通过！", "SUCCESS")
                return True
        
        self.log("设备验证超时", "ERROR")
        return False
    
    def login_github(self, page, context):
        """修复 GitHub 登录 unknown provider 错误"""
        self.log("登录 GitHub...", "STEP")
        
        # 强制等待页面完全加载
        page.wait_for_load_state('domcontentloaded', timeout=10000)
        time.sleep(2)
        
        try:
            # 显式定位并填写用户名密码（避免定位错误）
            login_input = page.locator('//*[@id="login_field"]').first
            login_input.fill(self.username)
            
            pass_input = page.locator('//*[@id="password"]').first
            pass_input.fill(self.password)
            
            self.log("已输入凭据")
        except Exception as e:
            self.log(f"输入失败: {e}", "ERROR")
            return False
        
        # 点击登录按钮（更精准的定位）
        try:
            page.locator('//*[@name="commit"]').first.click()
        except:
            page.locator('button[type="submit"]').first.click()
        
        # 延长登录后等待时间
        time.sleep(5)
        page.wait_for_load_state('networkidle', timeout=30000)
        
        current_url = page.url
        self.log(f"当前: {current_url}")
        
        # 设备验证
        if 'verified-device' in current_url or 'device-verification' in current_url:
            if not self.wait_device(page):
                return False
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
        
        # 检查错误
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        return True
    
    def run(self):
        """主流程"""
        self.log("\n" + "="*50)
        self.log("🚀 ClawCloud 自动登录")
        self.log("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            sys.exit(1)
        
        with sync_playwright() as p:
            # 修复 unknown provider 关键配置：添加更多浏览器参数
            browser = p.chromium.launch(
                headless=True, 
                args=[
                    '--no-sandbox',
                    '--disable-blink-features=AutomationControlled',
                    '--disable-dev-shm-usage',
                    '--disable-web-security',
                    '--ignore-certificate-errors'
                ]
            )
            
            # 模拟真实浏览器环境
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/121.0.0.0 Safari/537.36',
                locale='en-US',
                timezone_id='Europe/Berlin',  # 匹配 EU 服务器时区
                extra_http_headers={
                    'Accept-Language': 'en-US,en;q=0.9',
                    'Referer': 'https://github.com/'
                }
            )
            
            # 禁用自动化检测
            page = context.new_page()
            page.add_init_script("""
                Object.defineProperty(navigator, 'webdriver', {
                    get: () => undefined
                });
            """)
            
            try:
                # 预加载 Cookie（如果有）
                if self.gh_session:
                    try:
                        context.add_cookies([
                            {'name': 'user_session', 'value': self.gh_session, 'domain': 'github.com', 'path': '/'},
                            {'name': 'logged_in', 'value': 'yes', 'domain': 'github.com', 'path': '/'},
                            {'name': 'dotcom_user', 'value': self.username, 'domain': 'github.com', 'path': '/'}
                        ])
                        self.log("已加载 Session Cookie", "SUCCESS")
                    except:
                        self.log("加载 Cookie 失败", "WARN")
                
                # 步骤1：访问 ClawCloud（添加重试）
                self.log("步骤1: 打开 ClawCloud", "STEP")
                for retry in range(2):
                    try:
                        page.goto(SIGNIN_URL, timeout=60000)
                        break
                    except:
                        if retry == 0:
                            self.log("访问失败，重试中...", "WARN")
                            time.sleep(2)
                
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(3)  # 延长页面加载等待
                
                if 'signin' not in page.url.lower():
                    self.log("已登录！", "SUCCESS")
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    sys.exit(0)
                
                # 步骤2：点击 GitHub（更精准的定位）
                self.log("步骤2: 点击 GitHub", "STEP")
                if not self.click(page, [
                    '//button[contains(@class, "github")]',
                    '//a[contains(@href, "github")]',
                    '//*[text()="GitHub" or text()="Sign in with GitHub"]'
                ], "GitHub"):
                    self.log("找不到 GitHub 按钮", "ERROR")
                    sys.exit(1)
                
                time.sleep(5)  # 延长跳转等待
                page.wait_for_load_state('networkidle', timeout=30000)
                
                current_url = page.url
                self.log(f"当前: {current_url}")
                
                # 步骤3：GitHub 认证
                self.log("步骤3: GitHub 认证", "STEP")
                if 'github.com/login' in current_url or 'github.com/session' in current_url:
                    if not self.login_github(page, context):
                        self.log("GitHub 登录失败", "ERROR")
                        sys.exit(1)
                
                # 步骤4：等待重定向到 ClawCloud
                self.log("步骤4: 等待重定向", "STEP")
                for i in range(60):
                    current_url = page.url
                    if 'claw.cloud' in current_url and 'signin' not in current_url.lower():
                        self.log("重定向成功！", "SUCCESS")
                        break
                    time.sleep(1)
                    if i % 10 == 0:
                        self.log(f"  等待... ({i}秒)")
                
                # 保存新 Cookie
                new_session = self.get_session(context)
                if new_session:
                    self.save_cookie(new_session)
                else:
                    self.log("未获取到新 Cookie", "WARN")
                
                self.log("\n✅ 登录完成！")
                
            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                import traceback
                traceback.print_exc()
                sys.exit(1)
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()
