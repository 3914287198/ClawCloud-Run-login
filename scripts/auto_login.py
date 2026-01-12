"""
ClawCloud 自动登录脚本
- 自动检测区域跳转（如 ap-southeast-1.console.claw.cloud）
- 等待设备验证批准（30秒）
- 每次登录后自动更新 Cookie
- 钉钉通知
- 日志实时逐行输出
"""

import os
import sys
import time
import base64
import re
import hmac
import hashlib
import urllib.parse
import requests
from urllib.parse import urlparse
from playwright.sync_api import sync_playwright

# ==================== 配置 ====================
LOGIN_ENTRY_URL = "https://console.run.claw.cloud"
SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"
DEVICE_VERIFY_WAIT = 30
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))

# 钉钉配置
DINGTALK_ACCESS_TOKEN = os.environ.get('DINGTALK_ACCESS_TOKEN', '')
DINGTALK_SECRET = os.environ.get('DINGTALK_SECRET', '')


class DingTalk:
    """钉钉通知"""
    
    def __init__(self):
        self.token = DINGTALK_ACCESS_TOKEN
        self.secret = DINGTALK_SECRET
        self.ok = bool(self.token and self.secret)
        if self.ok:
            self._print_flush("✅ 钉钉通知已启用")
        else:
            self._print_flush("⚠️ 钉钉通知未启用（需要 DINGTALK_ACCESS_TOKEN/DINGTALK_SECRET）")
    
    def _get_sign(self):
        timestamp = str(round(time.time() * 1000))
        secret_enc = self.secret.encode('utf-8')
        string_to_sign = f"{timestamp}\n{self.secret}"
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return timestamp, sign
    
    def send(self, msg):
        if not self.ok:
            return
        try:
            timestamp, sign = self._get_sign()
            url = f"https://oapi.dingtalk.com/robot/send?access_token={self.token}&timestamp={timestamp}&sign={sign}"
            headers = {"Content-Type": "application/json;charset=utf-8"}
            msg = msg.replace("<b>", "**").replace("</b>", "**")
            msg = msg.replace("<code>", "`").replace("</code>", "`")
            data = {
                "msgtype": "text",
                "text": {"content": msg},
                "at": {"isAtAll": False}
            }
            response = requests.post(url, headers=headers, json=data, timeout=15)
            response.raise_for_status()
            result = response.json()
            if result.get('errcode') != 0:
                self._print_flush(f"❌ 钉钉发送失败: {result.get('errmsg')}")
        except Exception as e:
            self._print_flush(f"❌ 钉钉发送异常: {str(e)}")
    
    def photo(self, path, caption=""):
        if not self.ok or not os.path.exists(path):
            return
        try:
            upload_url = f"https://oapi.dingtalk.com/media/upload?access_token={self.token}&type=image"
            with open(path, 'rb') as f:
                files = {'media': f}
                upload_resp = requests.post(upload_url, files=files, timeout=30)
            upload_resp.raise_for_status()
            media_id = upload_resp.json().get('media_id')
            
            timestamp, sign = self._get_sign()
            send_url = f"https://oapi.dingtalk.com/robot/send?access_token={self.token}&timestamp={timestamp}&sign={sign}"
            headers = {"Content-Type": "application/json;charset=utf-8"}
            caption = caption.replace("<b>", "**").replace("</b>", "**")
            data = {
                "msgtype": "image",
                "image": {"media_id": media_id},
                "text": {"content": caption[:1024]}
            }
            response = requests.post(send_url, headers=headers, json=data, timeout=15)
            response.raise_for_status()
            result = response.json()
            if result.get('errcode') != 0:
                self._print_flush(f"❌ 钉钉发送图片失败: {result.get('errmsg')}")
        except Exception as e:
            self._print_flush(f"❌ 钉钉发送图片异常: {str(e)}")
    
    def flush_updates(self):
        return 0
    
    def wait_code(self, timeout=120):
        self.send(f"⚠️ 需要验证码登录，但钉钉无法接收消息，请手动处理！\n等待时间：{timeout} 秒")
        return None
    
    def _print_flush(self, msg):
        """强制刷新输出缓冲区"""
        print(msg)
        sys.stdout.flush()


class SecretUpdater:
    """GitHub Secret 更新器"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            self._print_flush("✅ Secret 自动更新已启用")
        else:
            self._print_flush("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")
    
    def update(self, name, value):
        if not self.ok:
            return False
        try:
            from nacl import encoding, public
            
            headers = {
                "Authorization": f"token {self.token}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            r = requests.get(f"https://api.github.com/repos/{self.repo}/actions/secrets/public-key", headers=headers, timeout=30)
            if r.status_code != 200:
                return False
            
            key_data = r.json()
            pk = public.PublicKey(key_data['key'].encode(), encoding.Base64Encoder())
            encrypted = public.SealedBox(pk).encrypt(value.encode())
            
            r = requests.put(f"https://api.github.com/repos/{self.repo}/actions/secrets/{name}", headers=headers, json={"encrypted_value": base64.b64encode(encrypted).decode(), "key_id": key_data['key_id']}, timeout=30)
            return r.status_code in [201, 204]
        except Exception as e:
            self._print_flush(f"更新 Secret 失败: {e}")
            return False
    
    def _print_flush(self, msg):
        print(msg)
        sys.stdout.flush()


class AutoLogin:
    """自动登录"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.tg = DingTalk()
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
        
        self.detected_region = None
        self.region_base_url = None
        
    def log(self, msg, level="INFO"):
        """实时打印日志（强制刷新缓冲区）"""
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
        sys.stdout.flush()  # 核心：强制刷新输出，让日志实时显示
        self.logs.append(line)
    
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
    
    def detect_region(self, url):
        try:
            parsed = urlparse(url)
            host = parsed.netloc
            
            if host.endswith('.console.claw.cloud'):
                region = host.replace('.console.claw.cloud', '')
                if region and region != 'console':
                    self.detected_region = region
                    self.region_base_url = f"https://{host}"
                    self.log(f"检测到区域: {region}", "SUCCESS")
                    self.log(f"区域 URL: {self.region_base_url}", "INFO")
                    return region
            
            if 'console.run.claw.cloud' in host or 'claw.cloud' in host:
                path = parsed.path
                region_match = re.search(r'/(?:region|r)/([a-z]+-[a-z]+-\d+)', path)
                if region_match:
                    region = region_match.group(1)
                    self.detected_region = region
                    self.region_base_url = f"https://{region}.console.claw.cloud"
                    self.log(f"从路径检测到区域: {region}", "SUCCESS")
                    return region
            
            self.log(f"未检测到特定区域，使用当前域名: {host}", "INFO")
            self.region_base_url = f"{parsed.scheme}://{parsed.netloc}"
            return None
            
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None
    
    def get_base_url(self):
        if self.region_base_url:
            return self.region_base_url
        return LOGIN_ENTRY_URL
    
    def get_session(self, context):
        try:
            for c in context.cookies():
                if c['name'] == 'user_session' and 'github' in c.get('domain', ''):
                    return c['value']
        except:
            pass
        return None
    
    def save_cookie(self, value):
        if not value:
            return
        
        self.log(f"新 Cookie: {value[:15]}...{value[-8:]}", "SUCCESS")
        
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 **Cookie 已自动更新**\n\nGH_SESSION 已保存")
        else:
            self.tg.send(f"""🔑 **新 Cookie**

请更新 Secret **GH_SESSION**:
`{value}`""")
            self.log("已通过钉钉发送 Cookie", "SUCCESS")
    
    def wait_device(self, page):
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")
        
        self.tg.send(f"""⚠️ **需要设备验证**

请在 {DEVICE_VERIFY_WAIT} 秒内批准：
1️⃣ 检查邮箱点击链接
2️⃣ 或在 GitHub App 批准""")
        
        if self.shots:
            self.tg.photo(self.shots[-1], "设备验证页面")
        
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒)")
                url = page.url
                if 'verified-device' not in url and 'device-verification' not in url:
                    self.log("设备验证通过！", "SUCCESS")
                    self.tg.send("✅ **设备验证通过**")
                    return True
                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
        
        if 'verified-device' not in page.url:
            return True
        
        self.log("设备验证超时", "ERROR")
        self.tg.send("❌ **设备验证超时**")
        return False
    
    def wait_two_factor_mobile(self, page):
        self.log(f"需要两步验证（GitHub Mobile），等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        
        shot = self.shot(page, "两步验证_mobile")
        self.tg.send(f"""⚠️ **需要两步验证（GitHub Mobile）**

请打开手机 GitHub App 批准本次登录（会让你确认一个数字）。
等待时间：{TWO_FACTOR_WAIT} 秒""")
        if shot:
            self.tg.photo(shot, "两步验证页面（数字在图里）")
        
        for i in range(TWO_FACTOR_WAIT):
            time.sleep(1)
            
            url = page.url
            if "github.com/sessions/two-factor/" not in url:
                self.log("两步验证通过！", "SUCCESS")
                self.tg.send("✅ **两步验证通过**")
                return True
            
            if "github.com/login" in url:
                self.log("两步验证后回到了登录页，需重新登录", "ERROR")
                return False
            
            if i % 10 == 0 and i != 0:
                self.log(f"  等待... ({i}/{TWO_FACTOR_WAIT}秒)")
                shot = self.shot(page, f"两步验证_{i}s")
                if shot:
                    self.tg.photo(shot, f"两步验证页面（第{i}秒）")
            
            if i % 30 == 0 and i != 0:
                try:
                    page.reload(timeout=30000)
                    page.wait_for_load_state('domcontentloaded', timeout=30000)
                except:
                    pass
        
        self.log("两步验证超时", "ERROR")
        self.tg.send("❌ **两步验证超时**")
        return False
    
    def handle_2fa_code_input(self, page):
        self.log("需要输入验证码", "WARN")
        shot = self.shot(page, "两步验证_code")
        
        try:
            more_options = [
                'a:has-text("Use an authentication app")',
                'a:has-text("Enter a code")',
                'button:has-text("Use an authentication app")',
                '[href*="two-factor/app"]'
            ]
            for sel in more_options:
                try:
                    el = page.locator(sel).first
                    if el.is_visible(timeout=2000):
                        el.click()
                        time.sleep(2)
                        page.wait_for_load_state('networkidle', timeout=15000)
                        self.log("已切换到验证码输入页面", "SUCCESS")
                        shot = self.shot(page, "两步验证_code_切换后")
                        break
                except:
                    pass
        except:
            pass
        
        self.tg.send(f"""🔐 **需要验证码登录**

钉钉无法接收消息，请手动处理验证码输入！
等待时间：{TWO_FACTOR_WAIT} 秒""")
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        self.log(f"等待验证码（{TWO_FACTOR_WAIT}秒）...", "WARN")
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)
        
        if not code:
            self.log("等待验证码超时（钉钉无法接收消息）", "ERROR")
            self.tg.send("❌ **等待验证码超时（钉钉无法接收消息）**")
            return False
        
        self.log("收到验证码，正在填入...", "SUCCESS")
        self.tg.send("✅ 收到验证码，正在填入...")
        
        selectors = [
            'input[autocomplete="one-time-code"]',
            'input[name="app_otp"]',
            'input[name="otp"]',
            'input#app_totp',
            'input#otp',
            'input[inputmode="numeric"]'
        ]
        
        for sel in selectors:
            try:
                el = page.locator(sel).first
                if el.is_visible(timeout=2000):
                    el.fill(code)
                    self.log(f"已填入验证码", "SUCCESS")
                    time.sleep(1)
                    
                    submitted = False
                    verify_btns = [
                        'button:has-text("Verify")',
                        'button[type="submit"]',
                        'input[type="submit"]'
                    ]
                    for btn_sel in verify_btns:
                        try:
                            btn = page.locator(btn_sel).first
                            if btn.is_visible(timeout=1000):
                                btn.click()
                                submitted = True
                                self.log("已点击 Verify 按钮", "SUCCESS")
                                break
                        except:
                            pass
                    
                    if not submitted:
                        page.keyboard.press("Enter")
                        self.log("已按 Enter 提交", "SUCCESS")
                    
                    time.sleep(3)
                    page.wait_for_load_state('networkidle', timeout=30000)
                    self.shot(page, "验证码提交后")
                    
                    if "github.com/sessions/two-factor/" not in page.url:
                        self.log("验证码验证通过！", "SUCCESS")
                        self.tg.send("✅ **验证码验证通过**")
                        return True
                    else:
                        self.log("验证码可能错误", "ERROR")
                        self.tg.send("❌ **验证码可能错误，请检查后重试**")
                        return False
            except:
                pass
        
        self.log("没找到验证码输入框", "ERROR")
        self.tg.send("❌ **没找到验证码输入框**")
        return False
    
    def login_github(self, page, context):
        self.log("登录 GitHub...", "STEP")
        self.shot(page, "github_登录页")
        
        try:
            page.locator('input[name="login"]').fill(self.username)
            page.locator('input[name="password"]').fill(self.password)
            self.log("已输入凭据")
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
        self.log(f"当前: {url}")
        
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "验证后")
        
        if 'two-factor' in page.url:
            self.log("需要两步验证！", "WARN")
            self.shot(page, "两步验证")
            
            if 'two-factor/mobile' in page.url:
                if not self.wait_two_factor_mobile(page):
                    return False
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                except:
                    pass
            
            else:
                if not self.handle_2fa_code_input(page):
                    return False
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                except:
                    pass
        
        try:
            err = page.locator('.flash-error').first
            if err.is_visible(timeout=2000):
                self.log(f"错误: {err.inner_text()}", "ERROR")
                return False
        except:
            pass
        
        return True
    
    def oauth(self, page):
        if 'github.com/login/oauth/authorize' in page.url:
            self.log("处理 OAuth...", "STEP")
            self.shot(page, "oauth")
            self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def wait_redirect(self, page, wait=60):
        self.log("等待重定向...", "STEP")
        for i in range(wait):
            url = page.url
            
            if 'claw.cloud' in url and 'signin' not in url.lower():
                self.log("重定向成功！", "SUCCESS")
                self.detect_region(url)
                return True
            
            if 'github.com/login/oauth/authorize' in url:
                self.oauth(page)
            
            time.sleep(1)
            if i % 10 == 0:
                self.log(f"  等待... ({i}秒)")
        
        self.log("重定向超时", "ERROR")
        return False
    
    def keepalive(self, page):
        self.log("保活...", "STEP")
        
        base_url = self.get_base_url()
        self.log(f"使用区域 URL: {base_url}", "INFO")
        
        pages_to_visit = [
            (f"{base_url}/", "控制台"),
            (f"{base_url}/apps", "应用"),
        ]
        
        if self.detected_region:
            self.log(f"当前区域: {self.detected_region}", "INFO")
        
        for url, name in pages_to_visit:
            try:
                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=15000)
                self.log(f"已访问: {name} ({url})", "SUCCESS")
                
                current_url = page.url
                if 'claw.cloud' in current_url:
                    self.detect_region(current_url)
                
                time.sleep(2)
            except Exception as e:
                self.log(f"访问 {name} 失败: {e}", "WARN")
        
        self.shot(page, "完成")
    
    def notify(self, ok, err=""):
        if not self.tg.ok:
            return
        
        region_info = f"\n**区域:** {self.detected_region or '默认'}" if self.detected_region else ""
        
        msg = f"""🤖 **ClawCloud 自动登录**

**状态:** {"✅ 成功" if ok else "❌ 失败"}
**用户:** {self.username}{region_info}
**时间:** {time.strftime('%Y-%m-%d %H:%M:%S')}"""
        
        if err:
            msg += f"\n**错误:** {err}"
        
        msg += "\n\n**日志:**\n" + "\n".join(self.logs[-6:])
        
        self.tg.send(msg)
        
        if self.shots:
            if not ok:
                for s in self.shots[-3:]:
                    self.tg.photo(s, s)
            else:
                self.tg.photo(self.shots[-1], "完成")
    
    def run(self):
        self.log("\n" + "="*50)
        self.log("🚀 ClawCloud 自动登录")
        self.log("="*50 + "\n")
        
        self.log(f"用户名: {self.username}")
        self.log(f"Session: {'有' if self.gh_session else '无'}")
        self.log(f"密码: {'有' if self.password else '无'}")
        self.log(f"登录入口: {LOGIN_ENTRY_URL}")
        
        if not self.username or not self.password:
            self.log("缺少凭据", "ERROR")
            self.notify(False, "凭据未配置")
            sys.exit(1)
        
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=['--no-sandbox'])
            context = browser.new_context(
                viewport={'width': 1920, 'height': 1080},
                user_agent='Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            )
            page = context.new_page()
            
            try:
                if self.gh_session:
                    try:
                        context.add_cookies([
                            {'name': 'user_session', 'value': self.gh_session, 'domain': 'github.com', 'path': '/'},
                            {'name': 'logged_in', 'value': 'yes', 'domain': 'github.com', 'path': '/'}
                        ])
                        self.log("已加载 Session Cookie", "SUCCESS")
                    except:
                        self.log("加载 Cookie 失败", "WARN")
                
                self.log("步骤1: 打开 ClawCloud 登录页", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(2)
                self.shot(page, "clawcloud")
                
                current_url = page.url
                self.log(f"当前 URL: {current_url}")
                
                if 'signin' not in current_url.lower() and 'claw.cloud' in current_url:
                    self.log("已登录！", "SUCCESS")
                    self.detect_region(current_url)
                    self.keepalive(page)
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    self.notify(True)
                    self.log("\n✅ 成功！\n")
                    return
                
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
                self.log(f"当前: {url}")
                
                self.log("步骤3: GitHub 认证", "STEP")
                
                if 'github.com/login' in url or 'github.com/session' in url:
                    if not self.login_github(page, context):
                        self.shot(page, "登录失败")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                elif 'github.com/login/oauth/authorize' in url:
                    self.log("Cookie 有效", "SUCCESS")
                    self.oauth(page)
                
                self.log("步骤4: 等待重定向", "STEP")
                if not self.wait_redirect(page):
                    self.shot(page, "重定向失败")
                    self.notify(False, "重定向失败")
                    sys.exit(1)
                
                self.shot(page, "重定向成功")
                
                self.log("步骤5: 验证", "STEP")
                current_url = page.url
                if 'claw.cloud' not in current_url or 'signin' in current_url.lower():
                    self.notify(False, "验证失败")
                    sys.exit(1)
                
                if not self.detected_region:
                    self.detect_region(current_url)
                
                self.keepalive(page)
                
                self.log("步骤6: 更新 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 Cookie", "WARN")
                
                self.notify(True)
                self.log("\n" + "="*50)
                self.log("✅ 成功！")
                if self.detected_region:
                    self.log(f"📍 区域: {self.detected_region}")
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
