#!/usr/bin/env python3
"""
ClawCloud 自动登录脚本
- 等待设备验证批准（30秒）
- 每次登录后自动更新 Cookie
- 钉钉实时通知（参数写死）
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
DEVICE_VERIFY_WAIT = 30

# 钉钉配置（写死到代码中）
DINGTALK_ACCESS_TOKEN = 'ada335c55c006ddc351eaad285a0d1d6d45e8e0a7a917170909edba0405eb34e'
DINGTALK_SECRET = 'SECe15f72fe6b681f05e537fc413fdb42e6f5da3571cdf4bca3c79c3a4e841398e4'


class DingTalk:
    """钉钉通知（参数写死 + 实时推送）"""
    
    def __init__(self):
        self.access_token = DINGTALK_ACCESS_TOKEN
        self.secret = DINGTALK_SECRET
        self.ok = bool(self.access_token and self.secret)
        if self.ok:
            self._print_and_flush("✅ 钉钉通知已启用（参数写死）")
        else:
            self._print_and_flush("⚠️ 钉钉通知未启用（参数缺失）")
    
    def _print_and_flush(self, msg):
        """实时打印并刷新输出（避免日志堆积）"""
        print(msg)
        sys.stdout.flush()  # 强制刷新输出缓冲区
    
    def generate_sign(self, timestamp):
        """生成签名"""
        string_to_sign = f'{timestamp}\n{self.secret}'
        hmac_code = hmac.new(self.secret.encode('utf-8'), string_to_sign.encode('utf-8'), digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return sign
    
    def send(self, msg, is_real_time=True):
        """发送钉钉消息（实时推送）"""
        if not self.ok:
            return
        
        if is_real_time:
            msg = f"🔍 【实时日志】\n{msg}"
        
        try:
            timestamp = int(round(time.time() * 1000))
            sign = self.generate_sign(timestamp)
            
            url = f'https://oapi.dingtalk.com/robot/send?access_token={self.access_token}&timestamp={timestamp}&sign={sign}'
            headers = {'Content-Type': 'application/json;charset=utf-8'}
            
            data = {
                "msgtype": "text",
                "text": {"content": msg},
                "at": {"isAtAll": False}
            }
            
            # 超时重试（2次）
            for retry in range(2):
                try:
                    response = requests.post(
                        url, 
                        headers=headers, 
                        data=json.dumps(data, ensure_ascii=False), 
                        timeout=10
                    )
                    if response.status_code == 200:
                        result = response.json()
                        if result.get('errcode') == 0:
                            self._print_and_flush("✅ 钉钉消息发送成功")
                        else:
                            self._print_and_flush(f"❌ 钉钉消息发送失败: {result.get('errmsg')}")
                    else:
                        self._print_and_flush(f"❌ 钉钉消息发送失败: HTTP {response.status_code}")
                    break
                except requests.exceptions.Timeout:
                    if retry == 0:
                        self._print_and_flush("⚠️ 钉钉消息发送超时，重试中...")
                        time.sleep(1)
                    else:
                        self._print_and_flush("❌ 钉钉消息发送超时，重试失败")
        except Exception as e:
            self._print_and_flush(f"❌ 钉钉消息发送异常: {e}")


class SecretUpdater:
    """GitHub Secret 更新器"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            self._print_and_flush("✅ Secret 自动更新已启用")
        else:
            self._print_and_flush("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")
    
    def _print_and_flush(self, msg):
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
            
            # 获取公钥
            r = requests.get(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key",
                headers=headers, timeout=30
            )
            if r.status_code != 200:
                return False
            
            key_data = r.json()
            pk = public.PublicKey(key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())
            
            # 更新 Secret
            r = requests.put(
                f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}",
                headers=headers,
                json={"encrypted_value": base64.b64encode(encrypted).decode(), "key_id": key_data['key_id']},
                timeout=30
            )
            return r.status_code in [201, 204]
        except Exception as e:
            self._print_and_flush(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    """自动登录（日志实时逐条输出）"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.dingtalk = DingTalk()
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
        
    def log(self, msg, level="INFO", push_dingtalk=True):
        """日志实时逐条输出 + 推送到钉钉"""
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        icon = icons.get(level, '•')
        line = f"{icon} {msg}"
        
        # 实时打印并强制刷新（关键：避免日志堆积）
        print(line)
        sys.stdout.flush()  # 立即输出到控制台
        self.logs.append(line)
        
        # 实时推送到钉钉
        if push_dingtalk and self.dingtalk.ok:
            if any(keyword in msg for keyword in [
                "步骤", "需要设备验证", "验证页面URL", "设备验证通过", 
                "设备验证超时", "当前:", "已点击", "登录失败", "重定向"
            ]):
                self.dingtalk.send(line)
    
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
                if el.is_visible(timeout=3000):
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
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
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
            self.dingtalk.send("🔑 <b>Cookie 已自动更新</b>\n\nGH_SESSION 已保存", is_real_time=False)
        else:
            self.dingtalk.send(f"""🔑 <b>新 Cookie</b>

请更新 Secret <b>GH_SESSION</b>:
<code>{value}</code>""", is_real_time=False)
            self.log("已通过钉钉发送 Cookie", "SUCCESS")
    
    def wait_device(self, page):
        """等待设备验证（实时日志）"""
        verify_url = page.url
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.log(f"验证页面URL: {verify_url}", "WARN")
        self.shot(page, "设备验证")
        
        # 单独发送验证提醒
        verify_msg = f"""⚠️ 【设备验证提醒】
请在 {DEVICE_VERIFY_WAIT} 秒内完成：
1️⃣ 点击链接：{verify_url}
2️⃣ 批准设备验证"""
        self.dingtalk.send(verify_msg, is_real_time=False)
        
        # 实时输出等待进度
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒)", push_dingtalk=False)
            # 实时检查验证状态
            url = page.url
            if 'verified-device' not in url and 'device-verification' not in url:
                self.log("设备验证通过！", "SUCCESS")
                self.dingtalk.send("✅ 设备验证通过，脚本继续执行", is_real_time=False)
                return True
        
        self.log("设备验证超时", "ERROR")
        self.dingtalk.send(f"❌ 设备验证超时（{DEVICE_VERIFY_WAIT}秒）\n链接：{verify_url}", is_real_time=False)
        return False
    
    def login_github(self, page, context):
        """登录 GitHub（实时日志）"""
        self.log("登录 GitHub...", "STEP")
        self.shot(page, "github_登录页")
        
        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            self.log("已输入凭据", push_dingtalk=False)
        except Exception as e:
            self.log(f"输入失败: {e}", "ERROR")
            return False
        
        self.shot(page, "github_已填写")
        
        try:
            page.locator('input[type="submit"], button[type="submit"]').first.click()
        except:
            pass
        
        time.sleep(3)
        page.wait_for_load_state('networkidle', timeout=30000)
        self.shot(page, "github_登录后")
        
        url = page.url
        self.log(f"当前: {url}", "INFO")
        
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "验证后")
        
        if 'two-factor' in page.url:
            self.log("需要两步验证！", "ERROR")
            self.dingtalk.send("❌ 需要两步验证", is_real_time=False)
            return False
        
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        return True
    
    def oauth(self, page):
        """处理 OAuth"""
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("处理 OAuth...", "STEP")
            self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def wait_redirect(self, page, wait=60):
        """等待重定向（实时日志）"""
        self.log("等待重定向...", "STEP")
        for i in range(wait):
            url = page.url
            if 'claw.cloud' in url and 'signin' not in url.lower():
                self.log("重定向成功！", "SUCCESS")
                return True
            if 'github.com/login/oauth/authorize' in url:
                self.oauth(page)
            time.sleep(1)
            if i % 10 == 0:
                self.log(f"  等待... ({i}秒)", push_dingtalk=False)
        self.log("重定向超时", "ERROR")
        return False
    
    def keepalive(self, page):
        """保活（实时日志）"""
        self.log("保活...", "STEP")
        for url, name in [(f"{CLAW_CLOUD_URL}/", "控制台"), (f"{CLAW_CLOUD_URL}/apps", "应用")]:
            try:
                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=15000)
                self.log(f"已访问: {name}", "SUCCESS")
                time.sleep(2)
            except:
                pass
        self.shot(page, "完成")
    
    def notify(self, ok, err=""):
        """最终汇总通知"""
        if not self.dingtalk.ok:
            return
        
        msg = f"""<b>🤖 ClawCloud 登录结果</b>
状态: {"✅ 成功" if ok else "❌ 失败"}
时间: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}"""
        if err:
            msg += f"\n错误: {err}"
        
        self.dingtalk.send(msg, is_real_time=False)
    
    def run(self):
        """主流程（实时日志）"""
        self.log("\n" + "="*50)
        self.log("🚀 ClawCloud 自动登录")
        self.log("="*50 + "\n")
        
        self.log(f"用户名: {self.username}", push_dingtalk=False)
        self.log(f"Session: {'有' if self.gh_session else '无'}", push_dingtalk=False)
        self.log(f"密码: {'有' if self.password else '无'}", push_dingtalk=False)
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) Chrome/120.0.0.0'
            )
            page = context.new_page()
            
            try:
                # 步骤1：打开 ClawCloud
                self.log("步骤1: 打开 ClawCloud", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(2)
                self.shot(page, "clawcloud")
                
                if 'signin' not in page.url.lower():
                    self.log("已登录！", "SUCCESS")
                    self.keepalive(page)
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    self.notify(True)
                    self.log("\n✅ 成功！\n")
                    return
                
                # 步骤2：点击 GitHub
                self.log("步骤2: 点击 GitHub", "STEP")
                if not self.click(page, [
                    'button:has-text("GitHub")',
                    'a:has-text("GitHub")',
                    '[data-provider="github"]'
                ], "GitHub"):
                    self.log("找不到按钮", "ERROR")
                    self.notify(False, "找不到 GitHub 按钮")
                    sys.exit(1)
                
                time.sleep(3)
                page.wait_for_load_state('networkidle', timeout=30000)
                self.shot(page, "点击后")
                
                url = page.url
                self.log(f"当前: {url}", "INFO")
                
                # 步骤3：GitHub 认证
                self.log("步骤3: GitHub 认证", "STEP")
                if 'github.com/login' in url or 'github.com/session' in url:
                    if not self.login_github(page, context):
                        self.shot(page, "登录失败")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                elif 'github.com/login/oauth/authorize' in url:
                    self.log("Cookie 有效", "SUCCESS")
                    self.oauth(page)
                
                # 步骤4：等待重定向
                self.log("步骤4: 等待重定向", "STEP")
                if not self.wait_redirect(page):
                    self.shot(page, "重定向失败")
                    self.notify(False, "重定向失败")
                    sys.exit(1)
                
                # 步骤5：验证 + 保活
                self.log("步骤5: 验证", "STEP")
                if 'claw.cloud' not in page.url or 'signin' in page.url.lower():
                    self.notify(False, "验证失败")
                    sys.exit(1)
                
                self.keepalive(page)
                
                # 步骤6：更新 Cookie
                self.log("步骤6: 更新 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 Cookie", "WARN")
                
                self.notify(True)
                self.log("\n" + "="*50)
                self.log("✅ 成功！")
                self.log("="*50 + "\n")
                
            except Exception as e:
                self.log(f"异常: {e}", "ERROR")
                self.shot(page, "异常")
                import traceback
                traceback.print_exc()
                self.notify(False, str(e))
                sys.exit(1)
            finally:
                browser.close()


if __name__ == "__main__":
    AutoLogin().run()
