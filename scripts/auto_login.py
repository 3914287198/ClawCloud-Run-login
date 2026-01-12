"""
ClawCloud 自动登录脚本
- 自动检测区域跳转（如 ap-southeast-1.console.claw.cloud）
- 等待设备验证批准（30秒）
- 每次登录后自动更新 Cookie
- 钉钉通知（替换原Telegram）
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
# 固定登录入口，OAuth后会自动跳转到实际区域
LOGIN_ENTRY_URL = "https://console.run.claw.cloud"
SIGNIN_URL = f"{LOGIN_ENTRY_URL}/signin"
DEVICE_VERIFY_WAIT = 30  # Mobile验证 默认等 30 秒
TWO_FACTOR_WAIT = int(os.environ.get("TWO_FACTOR_WAIT", "120"))  # 2FA验证 默认等 120 秒

# 钉钉配置（从环境变量读取）
DINGTALK_ACCESS_TOKEN = os.environ.get('DINGTALK_ACCESS_TOKEN', '')
DINGTALK_SECRET = os.environ.get('DINGTALK_SECRET', '')


class DingTalk:
    """钉钉通知（替换原Telegram）"""
    
    def __init__(self):
        self.token = DINGTALK_ACCESS_TOKEN
        self.secret = DINGTALK_SECRET
        self.ok = bool(self.token and self.secret)
        if self.ok:
            print("✅ 钉钉通知已启用")
        else:
            print("⚠️ 钉钉通知未启用（需要 DINGTALK_ACCESS_TOKEN/DINGTALK_SECRET）")
    
    def _get_sign(self):
        """生成钉钉签名"""
        timestamp = str(round(time.time() * 1000))
        secret_enc = self.secret.encode('utf-8')
        string_to_sign = f"{timestamp}\n{self.secret}"
        string_to_sign_enc = string_to_sign.encode('utf-8')
        hmac_code = hmac.new(secret_enc, string_to_sign_enc, digestmod=hashlib.sha256).digest()
        sign = urllib.parse.quote_plus(base64.b64encode(hmac_code))
        return timestamp, sign
    
    def send(self, msg):
        """发送钉钉文本消息（适配原tg.send）"""
        if not self.ok:
            return
        try:
            timestamp, sign = self._get_sign()
            url = f"https://oapi.dingtalk.com/robot/send?access_token={self.token}&timestamp={timestamp}&sign={sign}"
            headers = {"Content-Type": "application/json;charset=utf-8"}
            # 替换tg的HTML标签为钉钉支持的格式
            msg = msg.replace("<b>", "**").replace("</b>", "**")
            msg = msg.replace("<code>", "`").replace("</code>", "`")
            data = {
                "msgtype": "text",
                "text": {"content": msg},
                "at": {"isAtAll": False}
            }
            response = requests.post(
                url,
                headers=headers,
                json=data,
                timeout=15
            )
            response.raise_for_status()
            result = response.json()
            if result.get('errcode') != 0:
                print(f"❌ 钉钉发送失败: {result.get('errmsg')}")
        except Exception as e:
            print(f"❌ 钉钉发送异常: {str(e)}")
    
    def photo(self, path, caption=""):
        """发送钉钉图片消息（适配原tg.photo）"""
        if not self.ok or not os.path.exists(path):
            return
        try:
            # 钉钉发送图片需要先上传获取media_id
            upload_url = f"https://oapi.dingtalk.com/media/upload?access_token={self.token}&type=image"
            with open(path, 'rb') as f:
                files = {'media': f}
                upload_resp = requests.post(upload_url, files=files, timeout=30)
            upload_resp.raise_for_status()
            media_id = upload_resp.json().get('media_id')
            
            # 发送图片消息
            timestamp, sign = self._get_sign()
            send_url = f"https://oapi.dingtalk.com/robot/send?access_token={self.token}&timestamp={timestamp}&sign={sign}"
            headers = {"Content-Type": "application/json;charset=utf-8"}
            # 替换caption中的HTML标签
            caption = caption.replace("<b>", "**").replace("</b>", "**")
            data = {
                "msgtype": "image",
                "image": {"media_id": media_id},
                "text": {"content": caption[:1024]}  # 钉钉图片不支持caption，放到text里
            }
            response = requests.post(send_url, headers=headers, json=data, timeout=15)
            response.raise_for_status()
            result = response.json()
            if result.get('errcode') != 0:
                print(f"❌ 钉钉发送图片失败: {result.get('errmsg')}")
        except Exception as e:
            print(f"❌ 钉钉发送图片异常: {str(e)}")
    
    def flush_updates(self):
        """适配原tg.flush_updates，钉钉无需此功能，返回0"""
        return 0
    
    def wait_code(self, timeout=120):
        """
        适配原tg.wait_code（钉钉无消息接收功能，返回None）
        注：钉钉机器人无法接收消息，如需验证码输入需手动处理
        """
        self.send(f"⚠️ 需要验证码登录，但钉钉无法接收消息，请手动处理！\n等待时间：{timeout} 秒")
        return None


class SecretUpdater:
    """GitHub Secret 更新器（保持不变）"""
    
    def __init__(self):
        self.token = os.environ.get('REPO_TOKEN')
        self.repo = os.environ.get('GITHUB_REPOSITORY')
        self.ok = bool(self.token and self.repo)
        if self.ok:
            print("✅ Secret 自动更新已启用")
        else:
            print("⚠️ Secret 自动更新未启用（需要 REPO_TOKEN）")
    
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
            print(f"更新 Secret 失败: {e}")
            return False


class AutoLogin:
    """自动登录（仅替换tg为钉钉）"""
    
    def __init__(self):
        self.username = os.environ.get('GH_USERNAME')
        self.password = os.environ.get('GH_PASSWORD')
        self.gh_session = os.environ.get('GH_SESSION', '').strip()
        self.tg = DingTalk()  # 仅修改这里：Telegram → DingTalk
        self.secret = SecretUpdater()
        self.shots = []
        self.logs = []
        self.n = 0
        
        # 区域相关
        self.detected_region = None  # 检测到的区域，如 "ap-southeast-1"
        self.region_base_url = None  # 检测到的区域基础 URL
        
    def log(self, msg, level="INFO"):
        icons = {"INFO": "ℹ️", "SUCCESS": "✅", "ERROR": "❌", "WARN": "⚠️", "STEP": "🔹"}
        line = f"{icons.get(level, '•')} {msg}"
        print(line)
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
        """
        从 URL 中检测区域信息
        例如: https://ap-southeast-1.console.claw.cloud/... -> ap-southeast-1
        """
        try:
            parsed = urlparse(url)
            host = parsed.netloc  # 如 "ap-southeast-1.console.claw.cloud"
            
            # 检查是否是区域子域名格式
            # 格式: {region}.console.claw.cloud
            if host.endswith('.console.claw.cloud'):
                region = host.replace('.console.claw.cloud', '')
                if region and region != 'console':  # 排除无效情况
                    self.detected_region = region
                    self.region_base_url = f"https://{host}"
                    self.log(f"检测到区域: {region}", "SUCCESS")
                    self.log(f"区域 URL: {self.region_base_url}", "INFO")
                    return region
            
            # 如果是主域名 console.run.claw.cloud，可能还没跳转
            if 'console.run.claw.cloud' in host or 'claw.cloud' in host:
                # 尝试从路径或其他地方提取区域信息
                # 有些平台可能在路径中包含区域，如 /region/ap-southeast-1/...
                path = parsed.path
                region_match = re.search(r'/(?:region|r)/([a-z]+-[a-z]+-\d+)', path)
                if region_match:
                    region = region_match.group(1)
                    self.detected_region = region
                    self.region_base_url = f"https://{region}.console.claw.cloud"
                    self.log(f"从路径检测到区域: {region}", "SUCCESS")
                    return region
            
            self.log(f"未检测到特定区域，使用当前域名: {host}", "INFO")
            # 如果没有检测到区域，使用当前 URL 的基础部分
            self.region_base_url = f"{parsed.scheme}://{parsed.netloc}"
            return None
            
        except Exception as e:
            self.log(f"区域检测异常: {e}", "WARN")
            return None
    
    def get_base_url(self):
        """获取当前应该使用的基础 URL"""
        if self.region_base_url:
            return self.region_base_url
        return LOGIN_ENTRY_URL
    
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
        
        # 自动更新 Secret
        if self.secret.update('GH_SESSION', value):
            self.log("已自动更新 GH_SESSION", "SUCCESS")
            self.tg.send("🔑 **Cookie 已自动更新**\n\nGH_SESSION 已保存")  # 替换HTML标签为钉钉格式
        else:
            # 通过钉钉发送
            self.tg.send(f"""🔑 **新 Cookie**

请更新 Secret **GH_SESSION**:
`{value}`""")  # 替换HTML标签为钉钉格式
            self.log("已通过钉钉发送 Cookie", "SUCCESS")
    
    def wait_device(self, page):
        """等待设备验证"""
        self.log(f"需要设备验证，等待 {DEVICE_VERIFY_WAIT} 秒...", "WARN")
        self.shot(page, "设备验证")
        
        self.tg.send(f"""⚠️ **需要设备验证**

请在 {DEVICE_VERIFY_WAIT} 秒内批准：
1️⃣ 检查邮箱点击链接
2️⃣ 或在 GitHub App 批准""")  # 替换HTML标签为钉钉格式
        
        if self.shots:
            self.tg.photo(self.shots[-1], "设备验证页面")
        
        for i in range(DEVICE_VERIFY_WAIT):
            time.sleep(1)
            if i % 5 == 0:
                self.log(f"  等待... ({i}/{DEVICE_VERIFY_WAIT}秒)")
                url = page.url
                if 'verified-device' not in url and 'device-verification' not in url:
                    self.log("设备验证通过！", "SUCCESS")
                    self.tg.send("✅ **设备验证通过**")  # 替换HTML标签为钉钉格式
                    return True
                try:
                    page.reload(timeout=10000)
                    page.wait_for_load_state('networkidle', timeout=10000)
                except:
                    pass
        
        if 'verified-device' not in page.url:
            return True
        
        self.log("设备验证超时", "ERROR")
        self.tg.send("❌ **设备验证超时**")  # 替换HTML标签为钉钉格式
        return False
    
    def wait_two_factor_mobile(self, page):
        """等待 GitHub Mobile 两步验证批准，并把数字截图提前发钉钉"""
        self.log(f"需要两步验证（GitHub Mobile），等待 {TWO_FACTOR_WAIT} 秒...", "WARN")
        
        # 先截图并立刻发出去（让你看到数字）
        shot = self.shot(page, "两步验证_mobile")
        self.tg.send(f"""⚠️ **需要两步验证（GitHub Mobile）**

请打开手机 GitHub App 批准本次登录（会让你确认一个数字）。
等待时间：{TWO_FACTOR_WAIT} 秒""")  # 替换HTML标签为钉钉格式
        if shot:
            self.tg.photo(shot, "两步验证页面（数字在图里）")
        
        # 不要频繁 reload，避免把流程刷回登录页
        for i in range(TWO_FACTOR_WAIT):
            time.sleep(1)
            
            url = page.url
            
            # 如果离开 two-factor 流程页面，认为通过
            if "github.com/sessions/two-factor/" not in url:
                self.log("两步验证通过！", "SUCCESS")
                self.tg.send("✅ **两步验证通过**")  # 替换HTML标签为钉钉格式
                return True
            
            # 如果被刷回登录页，说明这次流程断了（不要硬等）
            if "github.com/login" in url:
                self.log("两步验证后回到了登录页，需重新登录", "ERROR")
                return False
            
            # 每 10 秒打印一次，并补发一次截图（防止你没看到数字）
            if i % 10 == 0 and i != 0:
                self.log(f"  等待... ({i}/{TWO_FACTOR_WAIT}秒)")
                shot = self.shot(page, f"两步验证_{i}s")
                if shot:
                    self.tg.photo(shot, f"两步验证页面（第{i}秒）")
            
            # 只在 30 秒、60 秒... 做一次轻刷新（可选，频率很低）
            if i % 30 == 0 and i != 0:
                try:
                    page.reload(timeout=30000)
                    page.wait_for_load_state('domcontentloaded', timeout=30000)
                except:
                    pass
        
        self.log("两步验证超时", "ERROR")
        self.tg.send("❌ **两步验证超时**")  # 替换HTML标签为钉钉格式
        return False
    
    def handle_2fa_code_input(self, page):
        """处理 TOTP 验证码输入（钉钉无法接收消息，提示手动处理）"""
        self.log("需要输入验证码", "WARN")
        shot = self.shot(page, "两步验证_code")
        
        # 先尝试点击"Use an authentication app"或类似按钮（如果在 mobile 页面）
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
        
        # 发送提示（钉钉无法接收消息，提示手动处理）
        self.tg.send(f"""🔐 **需要验证码登录**

钉钉无法接收消息，请手动处理验证码输入！
等待时间：{TWO_FACTOR_WAIT} 秒""")  # 替换HTML标签为钉钉格式
        if shot:
            self.tg.photo(shot, "两步验证页面")
        
        self.log(f"等待验证码（{TWO_FACTOR_WAIT}秒）...", "WARN")
        code = self.tg.wait_code(timeout=TWO_FACTOR_WAIT)  # 这里会返回None
        
        if not code:
            self.log("等待验证码超时（钉钉无法接收消息）", "ERROR")
            self.tg.send("❌ **等待验证码超时（钉钉无法接收消息）**")
            return False
        
        # 以下逻辑原脚本中code不为空时执行，钉钉场景下不会走到这里
        self.log("收到验证码，正在填入...", "SUCCESS")
        self.tg.send("✅ 收到验证码，正在填入...")
        
        # 常见 OTP 输入框 selector（优先级排序）
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
                    
                    # 优先点击 Verify 按钮，不行再 Enter
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
                    
                    # 检查是否通过
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
        """登录 GitHub"""
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
        
        # 设备验证
        if 'verified-device' in url or 'device-verification' in url:
            if not self.wait_device(page):
                return False
            time.sleep(2)
            page.wait_for_load_state('networkidle', timeout=30000)
            self.shot(page, "验证后")
        
        # 2FA
        if 'two-factor' in page.url:
            self.log("需要两步验证！", "WARN")
            self.shot(page, "两步验证")
            
            # GitHub Mobile：等待你在手机上批准
            if 'two-factor/mobile' in page.url:
                if not self.wait_two_factor_mobile(page):
                    return False
                # 通过后等页面稳定
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                except:
                    pass
            
            else:
                # 其它两步验证方式（TOTP/恢复码等），尝试通过钉钉提示手动处理
                if not self.handle_2fa_code_input(page):
                    return False
                # 通过后等页面稳定
                try:
                    page.wait_for_load_state('networkidle', timeout=30000)
                    time.sleep(2)
                except:
                    pass
        
        # 错误
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
            self.shot(page, "oauth")
            self.click(page, ['button[name="authorize"]', 'button:has-text("Authorize")'], "授权")
            time.sleep(3)
            page.wait_for_load_state('networkidle', timeout=30000)
    
    def wait_redirect(self, page, wait=60):
        """等待重定向并检测区域"""
        self.log("等待重定向...", "STEP")
        for i in range(wait):
            url = page.url
            
            # 检查是否已跳转到 claw.cloud
            if 'claw.cloud' in url and 'signin' not in url.lower():
                self.log("重定向成功！", "SUCCESS")
                
                # 检测并记录区域
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
        """保活 - 使用检测到的区域 URL"""
        self.log("保活...", "STEP")
        
        # 使用检测到的区域 URL，如果没有则使用默认
        base_url = self.get_base_url()
        self.log(f"使用区域 URL: {base_url}", "INFO")
        
        pages_to_visit = [
            (f"{base_url}/", "控制台"),
            (f"{base_url}/apps", "应用"),
        ]
        
        # 如果检测到了区域，可以额外访问一些区域特定页面
        if self.detected_region:
            self.log(f"当前区域: {self.detected_region}", "INFO")
        
        for url, name in pages_to_visit:
            try:
                page.goto(url, timeout=30000)
                page.wait_for_load_state('networkidle', timeout=15000)
                self.log(f"已访问: {name} ({url})", "SUCCESS")
                
                # 再次检测区域（以防中途跳转）
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
        print("\n" + "="*50)
        print("🚀 ClawCloud 自动登录")
        print("="*50 + "\n")
        
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
                # 预加载 Cookie
                if self.gh_session:
                    try:
                        context.add_cookies([
                            {'name': 'user_session', 'value': self.gh_session, 'domain': 'github.com', 'path': '/'},
                            {'name': 'logged_in', 'value': 'yes', 'domain': 'github.com', 'path': '/'}
                        ])
                        self.log("已加载 Session Cookie", "SUCCESS")
                    except:
                        self.log("加载 Cookie 失败", "WARN")
                
                # 1. 访问 ClawCloud 登录入口
                self.log("步骤1: 打开 ClawCloud 登录页", "STEP")
                page.goto(SIGNIN_URL, timeout=60000)
                page.wait_for_load_state('networkidle', timeout=30000)
                time.sleep(2)
                self.shot(page, "clawcloud")
                
                # 检查当前 URL，可能已经自动跳转到区域
                current_url = page.url
                self.log(f"当前 URL: {current_url}")
                
                if 'signin' not in current_url.lower() and 'claw.cloud' in current_url:
                    self.log("已登录！", "SUCCESS")
                    # 检测区域
                    self.detect_region(current_url)
                    self.keepalive(page)
                    # 提取并保存新 Cookie
                    new = self.get_session(context)
                    if new:
                        self.save_cookie(new)
                    self.notify(True)
                    print("\n✅ 成功！\n")
                    return
                
                # 2. 点击 GitHub
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
                
                # 3. GitHub 登录
                self.log("步骤3: GitHub 认证", "STEP")
                
                if 'github.com/login' in url or 'github.com/session' in url:
                    if not self.login_github(page, context):
                        self.shot(page, "登录失败")
                        self.notify(False, "GitHub 登录失败")
                        sys.exit(1)
                elif 'github.com/login/oauth/authorize' in url:
                    self.log("Cookie 有效", "SUCCESS")
                    self.oauth(page)
                
                # 4. 等待重定向（会自动检测区域）
                self.log("步骤4: 等待重定向", "STEP")
                if not self.wait_redirect(page):
                    self.shot(page, "重定向失败")
                    self.notify(False, "重定向失败")
                    sys.exit(1)
                
                self.shot(page, "重定向成功")
                
                # 5. 验证
                self.log("步骤5: 验证", "STEP")
                current_url = page.url
                if 'claw.cloud' not in current_url or 'signin' in current_url.lower():
                    self.notify(False, "验证失败")
                    sys.exit(1)
                
                # 再次确认区域检测
                if not self.detected_region:
                    self.detect_region(current_url)
                
                # 6. 保活（使用检测到的区域 URL）
                self.keepalive(page)
                
                # 7. 提取并保存新 Cookie
                self.log("步骤6: 更新 Cookie", "STEP")
                new = self.get_session(context)
                if new:
                    self.save_cookie(new)
                else:
                    self.log("未获取到新 Cookie", "WARN")
                
                self.notify(True)
                print("\n" + "="*50)
                print("✅ 成功！")
                if self.detected_region:
                    print(f"📍 区域: {self.detected_region}")
                print("="*50 + "\n")
                
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
