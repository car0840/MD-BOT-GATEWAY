# -*- coding: utf-8 -*-
"""SUPERNOVA QQ 机器人网关（多机器人版 · 内置管理面板）—— 独立部署于中转服务器。

== 架构 ==
单进程同时提供：
1. QQ 机器人网关：每个机器人一个独立线程 + 独立事件循环，可同时接入多个业务系统；
2. 内嵌管理面板：Flask 单页运维界面（默认 127.0.0.1:9000，可环境变量覆盖），
   支持登录、机器人增删改、状态监控、调用日志、会话管理与改密。

== 安全设计（行业安全基线）==
- 密码：PBKDF2 加盐哈希（werkzeug），数据库/配置文件不存明文
- 会话：服务端随机 token + 12h 过期；单一活跃会话 —— 新设备登录自动踢掉旧设备（防异地登录），
  面板可查看全部活跃会话并按需强制下线其他设备
- 暴力破解防护：同用户名连续 5 次失败锁定 15 分钟
- 敏感字段：app_secret 写入时自动用 QQ_BOT_SECRET_KEY(Fernet) 加密为 enc: 前缀，列表脱敏回显
- 鉴权：所有管理接口 Bearer token（不依赖 Cookie，免疫 CSRF）
- 审计：登录成功/失败/锁定、配置变更、改密、会话下线均记本地审计日志
- 响应头：X-Content-Type-Options / X-Frame-Options / Referrer-Policy / CSP
- 部署建议：面板默认只绑 127.0.0.1，经 Nginx/Caddy HTTPS 反代对外暴露，禁止裸 HTTP 公网直连

== 运行依赖 ==
pip install qq-botpy cryptography flask

== 启动 ==
python qqbot_gateway.py          （建议 MCSManager 守护，工作目录=本目录）

== 首次启动 ==
无 admin_config.json（且 .env 未设置 ADMIN_PASSWORD）时，首次访问面板会自动进入网页安装
向导：在页面中填写管理员用户名 / 密码 / 邮箱即可安全建号（一次性令牌防 CSRF/重放）。
若 .env 中设置了 ADMIN_USERNAME / ADMIN_PASSWORD，则仍按传统方式启动即自动建号。

== 环境变量 ==
  ADMIN_USERNAME / ADMIN_PASSWORD   初始管理员（仅首次创建时生效）
  QQ_BOT_SECRET_KEY                 Fernet 密钥（enc: 前缀 secret 的解密/加密密钥）
  GATEWAY_PANEL_HOST                面板绑定地址，默认 127.0.0.1
  GATEWAY_PANEL_PORT                面板端口，默认 9000
  GATEWAY_SESSION_TIMEOUT           会话超时秒数，默认 43200（12h）
"""
import os
import re
import sys
import json
import time
import signal
import secrets
import threading
import asyncio
import urllib.request
import urllib.error
import subprocess
from functools import wraps

import botpy
from botpy.message import GroupMessage
from cryptography.fernet import Fernet
try:
    from plugin_manager import PluginManager
except Exception:
    PluginManager = None

try:
    from flask import Flask, request, jsonify, render_template_string, make_response
    from werkzeug.security import generate_password_hash, check_password_hash
except ImportError:
    print('[PANEL] 缺少 Flask，请执行: pip install flask', flush=True)
    raise

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# ---------------- 文件路径 ----------------
BOTS_FILE = os.path.join(SCRIPT_DIR, 'bots_config.json')
ADMIN_FILE = os.path.join(SCRIPT_DIR, 'admin_config.json')
CALLS_FILE = os.path.join(SCRIPT_DIR, 'gateway_calls.jsonl')
AUDIT_FILE = os.path.join(SCRIPT_DIR, 'admin_audit.jsonl')
PLUGINS_DIR = os.path.join(SCRIPT_DIR, 'plugins')
TRUST_FILE = os.path.join(SCRIPT_DIR, 'trusted_plugins.json')
ENV_FILE = os.path.join(SCRIPT_DIR, '.env')

SECRET_PREFIX = 'enc:'
HEARTBEAT_INTERVAL = 30
SESSION_TIMEOUT = int(os.environ.get('GATEWAY_SESSION_TIMEOUT', '43200'))
PANEL_HOST = os.environ.get('GATEWAY_PANEL_HOST', '0.0.0.0')
PANEL_PORT = int(os.environ.get('GATEWAY_PANEL_PORT', '9000'))
MAX_FAILED = 5
LOCK_SECONDS = 900

# ---------------- 环境变量加载 ----------------
def _load_dotenv(path):
    if not os.path.exists(path):
        return
    try:
        with open(path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#') or '=' not in line:
                    continue
                k, _, v = line.partition('=')
                k, v = k.strip(), v.strip().strip('"').strip("'")
                if k and k not in os.environ:
                    os.environ[k] = v
    except Exception:
        pass

_load_dotenv(ENV_FILE)

# ---------------- 共享状态 ----------------
BOTS_STATE = {}        # app_id -> {'thread': Thread, 'alive': bool, 'last_heartbeat': float}
BOTS_LOCK = threading.Lock()
SESSION_STORE = {}     # token -> {'username','ip','created_at','expires_at'}
FAILED_LOGIN = {}      # username -> {'count','lock_until'}
CONFIG_LOCK = threading.Lock()
LOG_LOCK = threading.Lock()
SETUP_TOKEN = {'value': None}   # 安装向导一次性令牌（防 CSRF / 重放）
SETUP_LOCK = threading.Lock()
MAIL_CODES = {}        # key(purpose:username) -> {'code','expires','target','attempts'}
MAIL_SEND_RECORD = {}  # key -> 最近发送时间戳（防高频重发）
MAIL_LOCK = threading.Lock()
CLIENT_REFS = {}   # app_id -> QQBotClient（供插件跨进程发消息）
PLUGIN_MGR = None  # 插件管理器（main 中初始化）

_log = botpy.logging.get_logger()

HELP_TEXT = (
    'SUPERNOVA 评审查询助手使用说明：\n'
    '· 查工单：查询 <工单ID>（例：查询 1001）\n'
    '· 查邮箱：查询 <学员邮箱>（例：查询 user@example.com）\n'
    '· 查 QQ：查 <QQ号>（例：查 123456789）'
)


# ================= 工具函数 =================
def _decrypt_secret(stored):
    if not stored:
        return ''
    if not stored.startswith(SECRET_PREFIX):
        return stored
    key = os.environ.get('QQ_BOT_SECRET_KEY', '')
    if not key:
        return ''
    try:
        return Fernet(key.encode('utf-8')).decrypt(stored[len(SECRET_PREFIX):].encode('utf-8')).decode('utf-8')
    except Exception:
        return ''


def _encrypt_secret(plain):
    """面板写入 secret 时自动加密存储；无密钥则明文并降级提示。"""
    if not plain:
        return plain
    key = os.environ.get('QQ_BOT_SECRET_KEY', '')
    if key:
        try:
            return SECRET_PREFIX + Fernet(key.encode('utf-8')).encrypt(plain.encode('utf-8')).decode('utf-8')
        except Exception:
            pass
    return plain


def _mask(s):
    if not s:
        return ''
    return s[:4] + '****' + s[-4:] if len(s) > 8 else '****'


# ---------------- 邮件发送与邮箱验证码 ----------------
MAIL_CODE_TTL = 600            # 验证码有效期 10 分钟
MAIL_CODE_MAX_ATTEMPTS = 5     # 最多错误尝试次数
MAIL_RESEND_INTERVAL = 60      # 同一验证码 60 秒内不可重发
EMAIL_RE = re.compile(r'^[^@\s]+@[^@\s]+\.[^@\s]+$')


def _mask_email(email):
    if not email:
        return ''
    if '@' in email:
        local, _, domain = email.partition('@')
        if len(local) <= 2:
            return local[0] + '***@' + domain
        return local[0] + '***' + local[-1] + '@' + domain
    return (email[:2] + '***') if len(email) > 4 else '***'


def _get_smtp_config(admin=None):
    admin = admin if admin is not None else load_admin()
    if not admin:
        return {}
    return admin.get('smtp') or {}


def send_email(to_addr, subject, text):
    """发送邮件。SMTP 连接设 15s 超时，避免长阻塞导致 504；失败抛 RuntimeError。"""
    import smtplib
    import socket
    from email.mime.text import MIMEText
    from email.header import Header
    from email.utils import formataddr
    cfg = _get_smtp_config()
    host = str(cfg.get('host') or '').strip()
    if not host:
        raise RuntimeError('邮件服务未配置')
    user = str(cfg.get('user') or '').strip()
    pwd = _decrypt_secret(str(cfg.get('password') or ''))
    use_ssl = bool(cfg.get('use_ssl', True))
    port = int(cfg.get('port') or (465 if use_ssl else 25))
    from_addr = str(cfg.get('from_addr') or user or '').strip()
    from_name = str(cfg.get('from_name') or '').strip()
    if not from_addr:
        from_addr = user
    msg = MIMEText(text, 'plain', 'utf-8')
    msg['Subject'] = Header(subject, 'utf-8')
    if from_name:
        msg['From'] = formataddr((str(Header(from_name, 'utf-8')), from_addr))
    else:
        msg['From'] = from_addr
    msg['To'] = to_addr
    try:
        if use_ssl:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
            server.ehlo()
            try:
                server.starttls()
                server.ehlo()
            except Exception:
                pass
        try:
            if user:
                server.login(user, pwd)
            server.sendmail(from_addr, [to_addr], msg.as_string())
        finally:
            server.quit()
    except socket.timeout:
        raise RuntimeError('连接邮件服务器超时，请检查 SMTP 地址与端口')
    except smtplib.SMTPAuthenticationError:
        raise RuntimeError('SMTP 登录失败，请检查用户名/密码/授权码')
    except smtplib.SMTPException as e:
        raise RuntimeError('邮件发送失败: %s' % e)
    except OSError as e:
        raise RuntimeError('邮件发送失败: %s' % e)


def _gen_mail_code():
    return '%06d' % secrets.randbelow(1000000)


def _mail_code_key(purpose, username):
    return purpose + ':' + username


def _issue_mail_code(purpose, username, target):
    """生成并发送验证码前置：写入内存（实际发送由调用方完成）。返回 (ok, msg)。"""
    with MAIL_LOCK:
        key = _mail_code_key(purpose, username)
        now = time.time()
        last = MAIL_SEND_RECORD.get(key)
        if last and now - last < MAIL_RESEND_INTERVAL:
            left = int(MAIL_RESEND_INTERVAL - (now - last))
            return False, '发送过于频繁，请 %d 秒后再试' % left
        MAIL_CODES[key] = {
            'code': _gen_mail_code(),
            'expires': now + MAIL_CODE_TTL,
            'target': target,
            'attempts': 0,
        }
        MAIL_SEND_RECORD[key] = now
    return True, ''


def _consume_mail_code(purpose, username, code, target):
    """校验并消费验证码。返回 (ok, msg)。"""
    with MAIL_LOCK:
        key = _mail_code_key(purpose, username)
        rec = MAIL_CODES.get(key)
        if not rec:
            return False, '验证码不存在或已过期'
        if time.time() > rec['expires']:
            MAIL_CODES.pop(key, None)
            return False, '验证码已过期，请重新获取'
        if rec.get('target') != target:
            return False, '验证码与账号不匹配'
        if rec['attempts'] >= MAIL_CODE_MAX_ATTEMPTS:
            MAIL_CODES.pop(key, None)
            return False, '尝试次数过多，验证码已失效，请重新获取'
        if str(rec['code']) != str(code).strip():
            rec['attempts'] += 1
            return False, '验证码错误，剩余 %d 次机会' % (MAIL_CODE_MAX_ATTEMPTS - rec['attempts'])
        MAIL_CODES.pop(key, None)
        MAIL_SEND_RECORD.pop(key, None)
        return True, ''


def _mail_body(code, scene):
    if scene == 'reset':
        tip = '你正在使用邮箱找回密码。'
    elif scene == 'bind':
        tip = '你正在为管理面板账号绑定邮箱。'
    else:
        tip = '你正在解绑管理面板账号邮箱。'
    return ('%s\n\n你的验证码是：%s\n\n'
            '验证码 10 分钟内有效，请勿泄露给他人。\n'
            '若你未进行该操作，请忽略本邮件。') % (tip, code)


def _atomic_write(path, data):
    """原子写文件，避免并发/半写损坏。"""
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, path)


# ---------------- 配置读写 ----------------
def load_bots():
    if not os.path.exists(BOTS_FILE):
        return []
    try:
        with open(BOTS_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        _log.error(f'bots_config.json 解析失败: {e}')
        return []
    return data.get('bots') or []


def save_bots(bots):
    with CONFIG_LOCK:
        _atomic_write(BOTS_FILE, {'bots': bots})


def validate_bot(b):
    """校验单条机器人配置，返回 (错误信息 or None)。"""
    if not b.get('bot_name') or not str(b.get('bot_name', '')).strip():
        return '机器人名称不能为空'
    app_id = str(b.get('app_id', '')).strip()
    if not app_id:
        return 'AppID 不能为空'
    url = str(b.get('backend_url', '')).strip()
    if not re.match(r'^https?://', url):
        return 'backend_url 必须以 http:// 或 https:// 开头'
    token = str(b.get('internal_token', ''))
    if len(token) < 8:
        return 'internal_token 长度至少 8 位'
    return None


# ---------------- 管理账号 ----------------
def load_admin():
    if not os.path.exists(ADMIN_FILE):
        return None
    try:
        with open(ADMIN_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return None


def save_admin(data):
    _atomic_write(ADMIN_FILE, data)


def _needs_setup():
    """系统是否仍处于"未初始化"状态：无 admin_config.json 或其内无任何管理员。"""
    data = load_admin()
    return not data or not data.get('users')


def ensure_admin():
    """首次运行创建管理员：
    1) 已存在管理员 -> 直接返回；
    2) 环境变量显式设置了 ADMIN_PASSWORD -> 按环境变量自动创建（兼容传统部署）；
    3) 否则不创建，等待首次访问面板时的网页安装向导（页面中填写账号/密码/邮箱）。
    """
    data = load_admin()
    if data and data.get('users'):
        return data
    password = os.environ.get('ADMIN_PASSWORD') or ''
    if not password:
        return None
    username = (os.environ.get('ADMIN_USERNAME') or 'admin').strip()
    data = {'users': [{
        'username': username,
        'password_hash': generate_password_hash(password),
        'is_super': True,
        'email': (os.environ.get('ADMIN_EMAIL') or '').strip(),
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
    }]}
    save_admin(data)
    print(f'[PANEL] 已按环境变量 ADMIN_PASSWORD 创建初始管理员: {username}', flush=True)
    return data


# ---------------- 日志 ----------------
def _append_jsonl(path, entry):
    with LOG_LOCK:
        try:
            with open(path, 'a', encoding='utf-8') as f:
                f.write(json.dumps(entry, ensure_ascii=False) + '\n')
        except Exception:
            pass


def _audit(action, username, ip, detail=''):
    _append_jsonl(AUDIT_FILE, {
        'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
        'action': action, 'username': username, 'ip': ip, 'detail': detail,
    })


def dispatch_plugins(bot_app_id, hook, ctx):
    # 把事件分发给绑定该机器人的插件；返回 (handled, reply, outbox, error)
    if PLUGIN_MGR is None:
        return False, None, [], ''
    try:
        snap = PLUGIN_MGR.snapshot()
    except Exception:
        return False, None, [], ''
    for p in snap:
        if not p['enabled'] or not p['ready']:
            continue
        bind = p.get('bot_binding') or ''
        if bind and bind != bot_app_id:
            continue
        try:
            ok, value, outbox, err = PLUGIN_MGR.call(p['id'], hook, ctx)
        except Exception as e:
            _log.error(f'[PLUGIN] {p["id"]} 调用异常: {e}')
            continue
        if ok and (value or outbox):
            return True, value, outbox, err
    return False, None, [], ''


def _load_ssrf_allowlist():
    # SSRF 内网白名单：优先读 admin_config.json 的 ssrf.allowlist（面板可操作），
    # 兼容旧配置回退到环境变量 GATEWAY_SSRF_ALLOWED_CIDRS（逗号分隔 CIDR）
    import ipaddress
    raw_nets = []
    try:
        admin = load_admin()
        if admin and admin.get('ssrf') and admin['ssrf'].get('allowlist'):
            raw_nets = admin['ssrf']['allowlist']
    except Exception:
        pass
    if not raw_nets:
        env_raw = os.environ.get('GATEWAY_SSRF_ALLOWED_CIDRS', '').strip()
        if env_raw:
            raw_nets = [p.strip() for p in env_raw.split(',') if p.strip()]
    nets = []
    for part in raw_nets:
        part = str(part or '').strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            _log.warning(f'[SSRF] 忽略无效白名单网段: {part}')
    return nets


SSRF_ALLOWED_NETS = _load_ssrf_allowlist()


def _is_unsafe_ip(ip_str):
    # SSRF 防护：判定 IP 是否属于禁止访问的地址段（白名单网段内放行）
    try:
        import ipaddress
        ip = ipaddress.ip_address(ip_str.strip())
    except Exception:
        return True
    for net in SSRF_ALLOWED_NETS:
        if ip in net:
            return False
    return (ip.is_loopback or ip.is_private or ip.is_link_local
            or ip.is_multicast or ip.is_reserved or ip.is_unspecified)


def _assert_safe_url(url):
    # SSRF 防护：仅允许 http/https，且解析后所有 IP 均不得为内网/环回/保留地址
    import socket
    import urllib.parse
    p = urllib.parse.urlparse(url)
    if p.scheme not in ('http', 'https'):
        raise ValueError(f'仅允许 http/https 协议，非法 scheme: {p.scheme or "空"}')
    host = p.hostname
    if not host:
        raise ValueError('url 缺少主机名')
    addrs = set()
    try:
        for info in socket.getaddrinfo(host, None):
            addrs.add(info[4][0])
    except socket.gaierror as e:
        raise ValueError(f'域名解析失败: {host} ({e})')
    if not addrs:
        raise ValueError(f'域名无可用解析结果: {host}')
    for a in addrs:
        if _is_unsafe_ip(a):
            raise ValueError(f'禁止访问内网/环回/保留地址: {host} -> {a}')


def _safe_urlopen(url, method='GET', headers=None, data=None, timeout=10, max_size=1000000, max_redirects=5):
    # SSRF 安全的请求：手动跟随重定向，每跳重新校验目标地址，防止重定向绕过
    import urllib.request
    import urllib.parse

    class _NoAutoRedirect(urllib.request.HTTPRedirectHandler):
        # 禁止 urllib 自动重定向（避免跨协议 http->file 等绕过）
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None

    opener = urllib.request.build_opener(_NoAutoRedirect)
    current = url
    for _ in range(max_redirects + 1):
        _assert_safe_url(current)
        req = urllib.request.Request(current, method=method, headers=headers or {}, data=data)
        resp = opener.open(req, timeout=timeout)
        if resp.status in (301, 302, 303, 307, 308):
            loc = resp.headers.get('Location')
            resp.close()
            if not loc:
                raise ValueError('重定向缺少 Location')
            current = urllib.parse.urljoin(current, loc)
            if method in ('GET', 'HEAD'):
                pass
            else:
                # 301/302/303 后浏览器通常转为 GET；此处保守保持原方法并在下一跳重新校验
                pass
            continue
        try:
            body = resp.read(max_size).decode('utf-8', 'replace')
            return {'status': resp.status, 'headers': dict(resp.headers.items()), 'body': body}
        finally:
            resp.close()
    raise ValueError('重定向次数超过上限')


def _plugin_http_request(rec, args):
    # host.http_request 实现（同步，urllib，带 SSRF 防护）
    method = str(args.get('method') or 'GET').upper()
    url = args.get('url') or ''
    if not url:
        raise ValueError('url 为空')
    headers = dict(args.get('headers') or {})
    data = args.get('data')
    if isinstance(data, str):
        data = data.encode('utf-8')
    max_size = int(args.get('max_size') or 1000000)
    timeout = int(args.get('timeout') or 10)
    return _safe_urlopen(url, method=method, headers=headers, data=data,
                         timeout=timeout, max_size=max_size)


def _plugin_get_bots(rec, args):
    return [{'app_id': b['app_id'], 'bot_name': b.get('bot_name') or b['app_id'],
             'backend_url': b.get('backend_url') or ''} for b in load_bots()]


def _plugin_log(rec, args):
    _log.info(f"[PLUGIN:{rec.plugin_id}] {args.get('level')}: {args.get('msg')}")
    return True


def _plugin_emit(rec, args):
    _audit('plugin_event', rec.plugin_id, 'plugin',
           json.dumps({'name': args.get('name'), 'data': args.get('data')}, ensure_ascii=False)[:500])
    return True


def _plugin_send_from_host(bot, target, text):
    # 插件 send_text 的跨线程投递入口
    client = CLIENT_REFS.get(bot)
    if not client or not client._loop:
        return False
    try:
        asyncio.run_coroutine_threadsafe(
            client._send_plugin_msg({'bot': bot, 'target': target, 'text': text}), client._loop)
        return True
    except Exception as e:
        _log.error(f'[PLUGIN] send_text 投递失败: {e}')
        return False


def load_trust():
    try:
        with open(TRUST_FILE, 'r', encoding='utf-8') as f:
            return json.load(f)
    except Exception:
        return {}


def save_trust(data):
    tmp = TRUST_FILE + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=2)
    os.replace(tmp, TRUST_FILE)


def log_call(app_id, kind, param, ok, note=''):
    _append_jsonl(CALLS_FILE, {
        'ts': time.strftime('%Y-%m-%d %H:%M:%S'),
        'app_id': app_id, 'kind': kind, 'param': param, 'ok': ok, 'note': note,
    })


# ---------------- HTTP 调用 ----------------
def _http_post(url, payload, internal_token):
    data = json.dumps(payload).encode('utf-8')
    req = urllib.request.Request(url, data=data, method='POST')
    req.add_header('Content-Type', 'application/json')
    if internal_token:
        req.add_header('X-Service-Token', internal_token)
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = resp.read().decode('utf-8') or '{}'
            return json.loads(body), resp.status
    except urllib.error.HTTPError as e:
        try:
            body = e.read().decode('utf-8') or '{}'
            return json.loads(body), e.code
        except Exception:
            return {'error': f'HTTP {e.code}'}, e.code
    except Exception as e:
        return {'error': str(e)}, 0


# ---------------- 消息解析 ----------------
def _clean_content(content):
    text = content or ''
    text = re.sub(r'<@!?\d+>', ' ', text)
    text = re.sub(r'\[CQ:[^\]]+\]', ' ', text)
    text = re.sub(r'@\S+', ' ', text)
    return re.sub(r'\s+', ' ', text).strip()


def _parse_query(text):
    m = re.search(r'(?:查询|查|评审|review)\s*(?:工单|订单)?\s*[:：]?\s*(.+)', text, re.IGNORECASE)
    if not m:
        return None, None
    param = m.group(1).strip()
    if not param:
        return None, None
    if re.fullmatch(r'\d+', param):
        return ('ticket_id', param) if len(param) < 5 else ('qq', param)
    if '@' in param:
        return 'email', param
    return 'email', param


# ================= 机器人客户端 =================
class QQBotClient(botpy.Client):
    def __init__(self, app_id, config, **kwargs):
        super().__init__(**kwargs)
        self.app_id = app_id
        self.config = config
        self._heartbeat_started = False
        self._loop = None

    def _url(self, path):
        base = (self.config.get('backend_url') or '').rstrip('/')
        return f'{base}{path}'

    def _post(self, path, payload):
        return _http_post(self._url(path), payload, self.config.get('internal_token') or '')

    async def on_ready(self):
        self._loop = asyncio.get_running_loop()
        CLIENT_REFS[self.app_id] = self
        _log.info(f'gateway ready (app_id={self.app_id}, backend={self.config.get("backend_url")})')
        if not self._heartbeat_started:
            self._heartbeat_started = True
            asyncio.get_running_loop().create_task(self._heartbeat_loop())

    async def _heartbeat_loop(self):
        while True:
            await asyncio.sleep(HEARTBEAT_INTERVAL)
            with BOTS_LOCK:
                BOTS_STATE[self.app_id]['last_heartbeat'] = time.time()
            try:
                data, code = await asyncio.to_thread(
                    self._post, '/api/qq-bot/gateway/heartbeat', {'app_id': self.app_id}
                )
                if code != 200:
                    _log.warning(f'heartbeat failed (app_id={self.app_id}): {code} {data}')
            except Exception as e:
                _log.error(f'heartbeat error (app_id={self.app_id}): {e}')

    def _report_offline(self):
        try:
            self._post('/api/qq-bot/gateway/offline', {'app_id': self.app_id})
        except Exception as e:
            _log.error(f'report offline failed (app_id={self.app_id}): {e}')

    async def on_group_at_message_create(self, message: GroupMessage):
        text = _clean_content(message.content)
        if not text:
            return
        reply = None
        # ---- 插件分发优先 ----
        if PLUGIN_MGR is not None:
            ctx = {
                'bot': self.app_id,
                'bot_name': self.config.get('bot_name') or self.app_id,
                'backend_url': self.config.get('backend_url') or '',
                'internal_token': self.config.get('internal_token') or '',
                'text': text,
                'group_openid': message.group_openid,
                'user_openid': ((message.author or {}).get('member_openid') or ''),
                'msg_id': message.id,
                'source': 'group',
            }
            ok, value, outbox, perr = dispatch_plugins(self.app_id, 'on_message', ctx)
            if ok and value:
                reply = value if isinstance(value, str) else (value.get('reply') if isinstance(value, dict) else None)
            if outbox:
                for item in outbox:
                    try:
                        await self._send_plugin_msg(item)
                    except Exception as e:
                        _log.error(f'[PLUGIN] 插件消息发送失败: {e}')
            if not ok and perr:
                _log.warning(f'[PLUGIN] 分发失败({self.app_id}): {perr}')
        # ---- 默认内置查询逻辑（fallback，未被插件接管时） ----
        if reply is None:
            kind, param = _parse_query(text)
            if not kind or not param:
                reply = HELP_TEXT
            else:
                payload = {kind: param, 'app_id': self.app_id}
                data, code = await asyncio.to_thread(self._post, '/api/qq-bot/query-review', payload)
                ok = (code != 0 and data.get('ok'))
                log_call(self.app_id, kind, param, bool(ok), note='' if ok else str(data.get('error') or data.get('msg') or ''))
                if not ok:
                    reply = '查询服务暂时不可用，请稍后重试。'
                else:
                    reviews = data.get('reviews') or []
                    if not reviews:
                        reply = '未查询到相关评审记录。'
                    else:
                        lines = [f'共 {len(reviews)} 条评审记录：']
                        for idx, r in enumerate(reviews, 1):
                            status_txt = {
                                'pending': '待评审', 'reviewing': '评审中',
                                'pass': '已通过', 'fail': '未通过',
                            }.get(r.get('status'), r.get('status') or '-')
                            decision_txt = {
                                'pass': '通过', 'fail': '不通过',
                            }.get(r.get('decision'), r.get('decision') or '-')
                            lines.append(
                                f"{idx}. 工单{r.get('id', '')} | {r.get('student_name', '')} | "
                                f"{r.get('major_label', '')} | {status_txt} | "
                                f"评审:{r.get('examiner_name') or '-'} | "
                                f"复核:{r.get('reviewer_name') or '-'} | 结论:{decision_txt}"
                            )
                        reply = '\n'.join(lines)
                        if len(reply) > 2000:
                            reply = reply[:1990] + '…'
        try:
            await message._api.post_group_message(
                group_openid=message.group_openid,
                msg_type=0,
                msg_id=message.id,
                content=reply,
            )
        except Exception as e:
            _log.error(f'reply failed (app_id={self.app_id}): {e}')

    async def _send_plugin_msg(self, item):
        # 发送插件产生的消息；目标机器人不是自己时转交对应 client 的事件循环
        bot = item.get('bot')
        if bot and bot != self.app_id:
            client = CLIENT_REFS.get(bot)
            if client and client._loop:
                asyncio.run_coroutine_threadsafe(client._send_plugin_msg(item), client._loop)
            return
        target = item.get('target') or {}
        openid = target.get('group_openid') or target.get('user_openid')
        if not openid:
            return
        if 'group_openid' in target:
            await self._api.post_group_message(group_openid=openid, msg_type=0, content=item.get('text') or '')
        else:
            await self._api.post_c2c_message(openid=openid, msg_type=0, content=item.get('text') or '')


def _run_bot_thread(bot_cfg):
    if sys.version_info >= (3, 10):
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
    else:
        loop = asyncio.get_event_loop()

    app_id = bot_cfg['app_id']
    secret = _decrypt_secret(bot_cfg.get('app_secret') or '')
    if not secret:
        print(f'[QQBOT] app_secret 为空或解密失败 (app_id={app_id})，跳过该机器人', flush=True)
        with BOTS_LOCK:
            BOTS_STATE[app_id]['alive'] = False
        return

    intents = botpy.Intents(public_messages=True)
    client = QQBotClient(app_id=app_id, config=bot_cfg, intents=intents)
    CLIENT_REFS[app_id] = client
    try:
        print(f'[QQBOT] 启动机器人: {bot_cfg.get("bot_name") or app_id} (app_id={app_id})', flush=True)
        client.run(appid=app_id, secret=secret)
    except Exception as e:
        _log.error(f'gateway error (app_id={app_id}): {e}')
    finally:
        CLIENT_REFS.pop(app_id, None)
        client._report_offline()
        with BOTS_LOCK:
            BOTS_STATE[app_id]['alive'] = False


def start_all_bots(bots):
    """启动全部机器人线程；返回实际启动数。"""
    count = 0
    for b in bots:
        app_id = b['app_id']
        t = threading.Thread(target=_run_bot_thread, args=(b,), daemon=True)
        with BOTS_LOCK:
            BOTS_STATE[app_id] = {'thread': t, 'alive': True, 'last_heartbeat': None}
        t.start()
        count += 1
    return count


def _bot_snapshot(b):
    app_id = b['app_id']
    with BOTS_LOCK:
        st = BOTS_STATE.get(app_id, {})
        alive = bool(st.get('alive') and st.get('thread') and st['thread'].is_alive())
        hb = st.get('last_heartbeat')
    return {
        'bot_name': b.get('bot_name', ''),
        'app_id': app_id,
        'backend_url': b.get('backend_url', ''),
        'internal_token_masked': _mask(b.get('internal_token', '')),
        'secret_masked': _mask(b.get('app_secret', '')),
        'online': alive,
        'last_heartbeat': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(hb)) if hb else None,
    }


# ================= 管理面板（Flask）=================
app = Flask(__name__)
app.config['JSON_AS_ASCII'] = False


@app.route('/panel_bg.jpg')
def _panel_bg():
    from flask import send_from_directory
    return send_from_directory(SCRIPT_DIR, 'panel_bg.jpg')


@app.route('/panel_logo.png')
def _panel_logo():
    from flask import send_from_directory
    return send_from_directory(SCRIPT_DIR, 'panel_logo.png')



@app.after_request
def _security_headers(resp):
    resp.headers['X-Content-Type-Options'] = 'nosniff'
    resp.headers['X-Frame-Options'] = 'DENY'
    resp.headers['Referrer-Policy'] = 'no-referrer'
    resp.headers['Content-Security-Policy'] = "default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self' 'unsafe-inline'; img-src 'self' data:"
    return resp


def _current_user():
    auth = request.headers.get('Authorization', '')
    token = auth[7:] if auth.startswith('Bearer ') else ''
    s = SESSION_STORE.get(token)
    if not s or time.time() > s['expires_at']:
        SESSION_STORE.pop(token, None)
        return None, None
    s['last_active'] = time.time()
    return s['username'], token


def require_auth(fn):
    @wraps(fn)
    def wrapper(*args, **kwargs):
        username, _ = _current_user()
        if not username:
            return jsonify({'ok': False, 'msg': '未登录或会话已过期'}), 401
        admin = load_admin()
        u = next((x for x in (admin.get('users', []) if admin else []) if x.get('username') == username), None)
        if u is not None and not u.get('enabled', True):
            for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
                SESSION_STORE.pop(t, None)
            return jsonify({'ok': False, 'msg': '账号已被停用，请联系超级管理员'}), 403
        request._g_username = username
        return fn(*args, **kwargs)
    return wrapper


# ---------------- 首次安装向导（WP 风格：面板内建号，一次性令牌防 CSRF/重放） ----------------
@app.route('/api/setup/status', methods=['GET'])
def setup_status():
    need = _needs_setup()
    token = None
    if need:
        with SETUP_LOCK:
            if not SETUP_TOKEN['value']:
                SETUP_TOKEN['value'] = secrets.token_urlsafe(24)
            token = SETUP_TOKEN['value']
    return jsonify({'ok': True, 'needs_setup': need, 'token': token})


@app.route('/api/setup', methods=['POST'])
def setup_complete():
    """仅系统未初始化时可调用；一次性令牌防 CSRF/重放；校验与存储结构同「新增管理员」，保证联动一致。"""
    if not _needs_setup():
        return jsonify({'ok': False, 'msg': '系统已完成初始化'}), 403
    data = request.get_json(silent=True) or {}
    token = str(data.get('token') or '')
    username = str(data.get('username') or '').strip()
    password = str(data.get('password') or '')
    email = str(data.get('email') or '').strip()
    with SETUP_LOCK:
        if not SETUP_TOKEN['value'] or token != SETUP_TOKEN['value']:
            return jsonify({'ok': False, 'msg': '校验令牌无效，请刷新页面重试'}), 403
        if not username:
            return jsonify({'ok': False, 'msg': '用户名不能为空'}), 400
        if len(password) < 8:
            return jsonify({'ok': False, 'msg': '密码至少 8 位'}), 400
        if not email or not EMAIL_RE.match(email):
            return jsonify({'ok': False, 'msg': '请输入正确的邮箱'}), 400
        # 并发 / 重复提交保护：锁内再次确认仍未初始化
        if not _needs_setup():
            return jsonify({'ok': False, 'msg': '系统已完成初始化'}), 403
        with CONFIG_LOCK:
            admin = load_admin()
            if admin and admin.get('users'):
                return jsonify({'ok': False, 'msg': '系统已完成初始化'}), 403
            save_admin({'users': [{
                'username': username,
                'password_hash': generate_password_hash(password),
                'is_super': True,
                'email': email,
                'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
            }]})
            SETUP_TOKEN['value'] = None  # 一次性令牌：初始化完成后立即作废
    _audit('setup_complete', username, request.remote_addr or '', '安装向导创建初始超管')
    return jsonify({'ok': True, 'msg': '初始化完成', 'username': username})


@app.route('/')
def index():
    resp = make_response(render_template_string(ADMIN_HTML))
    resp.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
    resp.headers['Pragma'] = 'no-cache'
    return resp


@app.route('/api/login', methods=['POST'])
def login():
    data = request.get_json(silent=True) or {}
    username = str(data.get('username') or '').strip()
    password = str(data.get('password') or '')
    ip = request.remote_addr or ''
    now = time.time()

    f = FAILED_LOGIN.get(username)
    if f and f.get('lock_until') and now < f['lock_until']:
        _audit('login_blocked', username, ip)
        until = time.strftime('%H:%M:%S', time.localtime(f['lock_until']))
        return jsonify({'ok': False, 'msg': f'失败次数过多，已锁定至 {until}'}), 429

    admin = load_admin()
    user = None
    if admin:
        user = next((u for u in admin.get('users', []) if u['username'] == username), None)

    if not user or not check_password_hash(user['password_hash'], password):
        f = FAILED_LOGIN.setdefault(username, {'count': 0, 'lock_until': 0})
        f['count'] = f.get('count', 0) + 1
        if f['count'] >= MAX_FAILED:
            f['lock_until'] = now + LOCK_SECONDS
            f['count'] = 0
            _audit('login_lock', username, ip)
        else:
            _audit('login_fail', username, ip)
        return jsonify({'ok': False, 'msg': '用户名或密码错误'}), 401

    if not user.get('enabled', True):
        _audit('login_disabled', username, ip)
        return jsonify({'ok': False, 'msg': '账号已被停用，请联系超级管理员'}), 403

    FAILED_LOGIN.pop(username, None)
    token = secrets.token_urlsafe(32)
    # 防异地登录：新登录踢掉该账号全部旧会话（单活跃会话）
    for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
        _audit('session_kicked', username, SESSION_STORE[t].get('ip'), '新设备登录，旧会话已下线')
        SESSION_STORE.pop(t, None)
    SESSION_STORE[token] = {
        'username': username, 'ip': ip,
        'created_at': now, 'expires_at': now + SESSION_TIMEOUT,
    }
    _audit('login_success', username, ip)
    return jsonify({'ok': True, 'token': token, 'username': username, 'is_super': is_super_admin(admin, username)})


@app.route('/api/logout', methods=['POST'])
@require_auth
def logout():
    auth = request.headers.get('Authorization', '')
    token = auth[7:] if auth.startswith('Bearer ') else ''
    SESSION_STORE.pop(token, None)
    _audit('logout', request._g_username, request.remote_addr or '')
    return jsonify({'ok': True})


@app.route('/api/session', methods=['GET'])
@require_auth
def get_session():
    username, token = _current_user()
    s = SESSION_STORE.get(token)
    admin = load_admin()
    user = _find_user(admin, username) if admin else None
    return jsonify({
        'ok': True,
        'username': username,
        'is_super': is_super_admin(admin, username),
        'email': (user or {}).get('email') or '',
        'login_ip': s['ip'],
        'login_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['created_at'])),
        'expires_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['expires_at'])),
    })


@app.route('/api/sessions', methods=['GET'])
@require_auth
def list_sessions():
    username = request._g_username
    rows = []
    for token, s in SESSION_STORE.items():
        if s['username'] != username:
            continue
        rows.append({
            'token': token[:8],
            'ip': s['ip'],
            'created_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['created_at'])),
            'expires_at': time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(s['expires_at'])),
            'current': _current_user()[1] == token,
        })
    return jsonify({'ok': True, 'sessions': rows})


@app.route('/api/sessions/kill-others', methods=['POST'])
@require_auth
def kill_others():
    username = request._g_username
    my_token = _current_user()[1]
    for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username and t != my_token]:
        SESSION_STORE.pop(t, None)
    _audit('session_kill_others', username, request.remote_addr or '')
    return jsonify({'ok': True, 'msg': '其他会话已下线'})


@app.route('/api/password', methods=['POST'])
@require_auth
def change_password():
    data = request.get_json(silent=True) or {}
    old_pwd = str(data.get('old_pwd') or '')
    new_pwd = str(data.get('new_pwd') or '')
    username = request._g_username
    if len(new_pwd) < 8:
        return jsonify({'ok': False, 'msg': '新密码至少 8 位'}), 400
    admin = load_admin()
    user = next((u for u in admin.get('users', []) if u['username'] == username), None)
    if not user or not check_password_hash(user['password_hash'], old_pwd):
        return jsonify({'ok': False, 'msg': '原密码错误'}), 400
    user['password_hash'] = generate_password_hash(new_pwd)
    save_admin(admin)
    # 改密后全端踢下线
    for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
        SESSION_STORE.pop(t, None)
    _audit('password_change', username, request.remote_addr or '')
    return jsonify({'ok': True, 'msg': '密码已修改，请重新登录'})


# ---------------- 邮箱绑定 / 找回密码 / SMTP 配置 ----------------
def _find_user(admin, username):
    if not admin:
        return None
    return next((u for u in admin.get('users', []) if u.get('username') == username), None)


def _email_taken(admin, email, exclude_username=''):
    if not admin:
        return False
    for u in admin.get('users', []):
        if u.get('username') == exclude_username:
            continue
        if u.get('email') and u['email'].lower() == email.lower():
            return True
    return False


@app.route('/api/account', methods=['GET'])
@require_auth
def get_account():
    username = request._g_username
    admin = load_admin()
    user = _find_user(admin, username)
    email = (user or {}).get('email') or ''
    return jsonify({
        'ok': True,
        'username': username,
        'email': email,
        'has_email': bool(email),
        'is_super': is_super_admin(admin, username),
        'smtp_configured': bool(_get_smtp_config(admin).get('host')),
    })


@app.route('/api/account/email', methods=['POST'])
@require_auth
def account_bind_email():
    """第一步：校验邮箱未被占用并发送绑定验证码。"""
    username = request._g_username
    admin = load_admin()
    user = _find_user(admin, username)
    data = request.get_json(silent=True) or {}
    email = str(data.get('email') or '').strip().lower()
    if not email or not EMAIL_RE.match(email):
        return jsonify({'ok': False, 'msg': '邮箱格式不正确'}), 400
    if (user or {}).get('email'):
        return jsonify({'ok': False, 'msg': '当前账号已绑定邮箱，请先解绑'}), 400
    if _email_taken(admin, email, username):
        return jsonify({'ok': False, 'msg': '该邮箱已被其他账号绑定'}), 400
    ok, msg = _issue_mail_code('bind', username, email)
    if not ok:
        return jsonify({'ok': False, 'msg': msg}), 429
    try:
        send_email(email, '【网关管理面板】邮箱绑定验证码', _mail_body(MAIL_CODES[_mail_code_key('bind', username)]['code'], 'bind'))
    except RuntimeError as e:
        with MAIL_LOCK:
            MAIL_CODES.pop(_mail_code_key('bind', username), None)
            MAIL_SEND_RECORD.pop(_mail_code_key('bind', username), None)
        _audit('mail_send_fail', username, request.remote_addr or '', '绑定验证码发送失败: ' + str(e))
        return jsonify({'ok': False, 'msg': str(e)}), 500
    _audit('mail_bind_send', username, request.remote_addr or '', '向 ' + _mask_email(email) + ' 发送绑定验证码')
    return jsonify({'ok': True, 'msg': '验证码已发送到 ' + _mask_email(email) + '，10 分钟内有效'})


@app.route('/api/account/email/verify', methods=['POST'])
@require_auth
def account_bind_email_verify():
    """第二步：校验验证码后完成绑定。"""
    username = request._g_username
    admin = load_admin()
    user = _find_user(admin, username)
    data = request.get_json(silent=True) or {}
    email = str(data.get('email') or '').strip().lower()
    code = str(data.get('code') or '').strip()
    if (user or {}).get('email'):
        return jsonify({'ok': False, 'msg': '当前账号已绑定邮箱'}), 400
    if _email_taken(admin, email, username):
        return jsonify({'ok': False, 'msg': '该邮箱已被其他账号绑定'}), 400
    ok, msg = _consume_mail_code('bind', username, code, email)
    if not ok:
        return jsonify({'ok': False, 'msg': msg}), 400
    user['email'] = email
    save_admin(admin)
    _audit('mail_bind', username, request.remote_addr or '', '绑定邮箱: ' + _mask_email(email))
    return jsonify({'ok': True, 'msg': '邮箱绑定成功'})


@app.route('/api/account/email/unbind', methods=['POST'])
@require_auth
def account_unbind_email():
    """解绑：send=true 发送验证码到已绑定邮箱；传 code 则校验并解绑。"""
    username = request._g_username
    admin = load_admin()
    user = _find_user(admin, username)
    email = (user or {}).get('email') or ''
    if not email:
        return jsonify({'ok': False, 'msg': '当前账号未绑定邮箱'}), 400
    data = request.get_json(silent=True) or {}
    code = str(data.get('code') or '').strip()
    if not code:
        ok, msg = _issue_mail_code('unbind', username, email)
        if not ok:
            return jsonify({'ok': False, 'msg': msg}), 429
        try:
            send_email(email, '【网关管理面板】解绑邮箱验证码', _mail_body(MAIL_CODES[_mail_code_key('unbind', username)]['code'], 'unbind'))
        except RuntimeError as e:
            with MAIL_LOCK:
                MAIL_CODES.pop(_mail_code_key('unbind', username), None)
                MAIL_SEND_RECORD.pop(_mail_code_key('unbind', username), None)
            return jsonify({'ok': False, 'msg': str(e)}), 500
        return jsonify({'ok': True, 'msg': '验证码已发送到 ' + _mask_email(email)})
    ok, msg = _consume_mail_code('unbind', username, code, email)
    if not ok:
        return jsonify({'ok': False, 'msg': msg}), 400
    user.pop('email', None)
    save_admin(admin)
    _audit('mail_unbind', username, request.remote_addr or '', '解绑邮箱: ' + _mask_email(email))
    return jsonify({'ok': True, 'msg': '邮箱已解绑'})


@app.route('/api/password/forgot', methods=['POST'])
def password_forgot():
    """找回密码第一步：用户名+绑定邮箱匹配则发送验证码。统一提示防枚举。"""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username') or '').strip()
    email = str(data.get('email') or '').strip().lower()
    ip = request.remote_addr or ''
    if not username or not email or not EMAIL_RE.match(email):
        return jsonify({'ok': False, 'msg': '请填写正确的用户名和邮箱'}), 400
    if not _get_smtp_config().get('host'):
        return jsonify({'ok': False, 'msg': '系统未配置邮件服务，请联系管理员'}), 400
    admin = load_admin()
    user = _find_user(admin, username)
    matched = bool(user and user.get('email') and user['email'].lower() == email)
    if matched:
        ok, msg = _issue_mail_code('reset', username, email)
        if not ok:
            return jsonify({'ok': False, 'msg': msg}), 429
        try:
            send_email(email, '【网关管理面板】找回密码验证码', _mail_body(MAIL_CODES[_mail_code_key('reset', username)]['code'], 'reset'))
        except RuntimeError as e:
            with MAIL_LOCK:
                MAIL_CODES.pop(_mail_code_key('reset', username), None)
                MAIL_SEND_RECORD.pop(_mail_code_key('reset', username), None)
            _audit('mail_send_fail', username, ip, '找回密码验证码发送失败: ' + str(e))
            return jsonify({'ok': False, 'msg': '邮件发送失败: ' + str(e)}), 500
        _audit('password_forgot_send', username, ip, '向 ' + _mask_email(email) + ' 发送找回密码验证码')
    return jsonify({'ok': True, 'msg': '若该账号存在且邮箱匹配，验证码已发送到绑定邮箱'})


@app.route('/api/password/reset', methods=['POST'])
def password_reset():
    """找回密码第二步：验证码校验后重置密码并踢下线。"""
    data = request.get_json(silent=True) or {}
    username = str(data.get('username') or '').strip()
    email = str(data.get('email') or '').strip().lower()
    code = str(data.get('code') or '').strip()
    new_pwd = str(data.get('password') or '')
    if len(new_pwd) < 8:
        return jsonify({'ok': False, 'msg': '新密码至少 8 位'}), 400
    if not username or not email or not code:
        return jsonify({'ok': False, 'msg': '参数不完整'}), 400
    admin = load_admin()
    user = _find_user(admin, username)
    if not user or not user.get('email') or user['email'].lower() != email:
        return jsonify({'ok': False, 'msg': '账号或绑定邮箱不匹配'}), 400
    ok, msg = _consume_mail_code('reset', username, code, email)
    if not ok:
        return jsonify({'ok': False, 'msg': msg}), 400
    user['password_hash'] = generate_password_hash(new_pwd)
    save_admin(admin)
    for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
        SESSION_STORE.pop(t, None)
    _audit('password_reset', username, request.remote_addr or '', '通过绑定邮箱找回密码')
    return jsonify({'ok': True, 'msg': '密码已重置，请使用新密码登录'})


@app.route('/api/mail/config', methods=['GET', 'POST'])
@require_auth
def mail_config():
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可配置邮件服务'}), 403
    if request.method == 'GET':
        cfg = _get_smtp_config(admin)
        return jsonify({'ok': True, 'config': {
            'host': cfg.get('host', ''),
            'port': cfg.get('port', 465),
            'use_ssl': cfg.get('use_ssl', True),
            'user': cfg.get('user', ''),
            'from_addr': cfg.get('from_addr', ''),
            'from_name': cfg.get('from_name', ''),
            'has_password': bool(cfg.get('password')),
            'configured': bool(cfg.get('host')),
        }})
    data = request.get_json(silent=True) or {}
    host = str(data.get('host') or '').strip()
    if not host:
        return jsonify({'ok': False, 'msg': 'SMTP 服务器地址不能为空'}), 400
    cfg = _get_smtp_config(admin)
    try:
        port = int(data.get('port') or (465 if data.get('use_ssl', True) else 25))
    except (TypeError, ValueError):
        port = 465
    cfg['host'] = host
    cfg['port'] = port
    cfg['use_ssl'] = bool(data.get('use_ssl', True))
    cfg['user'] = str(data.get('user') or '').strip()
    new_pwd = str(data.get('password') or '')
    if new_pwd:
        cfg['password'] = _encrypt_secret(new_pwd)
    cfg['from_addr'] = str(data.get('from_addr') or '').strip()
    cfg['from_name'] = str(data.get('from_name') or '').strip()
    admin['smtp'] = cfg
    save_admin(admin)
    _audit('mail_config_save', me, request.remote_addr or '', '保存 SMTP 配置: ' + host)
    return jsonify({'ok': True, 'msg': 'SMTP 配置已保存'})


@app.route('/api/mail/test', methods=['POST'])
@require_auth
def mail_test():
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可发送测试邮件'}), 403
    data = request.get_json(silent=True) or {}
    to = str(data.get('to') or '').strip()
    if not to or not EMAIL_RE.match(to):
        return jsonify({'ok': False, 'msg': '请填写正确的测试收件邮箱'}), 400
    try:
        send_email(to, '【网关管理面板】SMTP 测试邮件',
                   '这是一封测试邮件，说明 SMTP 邮件服务配置成功。\n\n时间：%s' % time.strftime('%Y-%m-%d %H:%M:%S'))
    except RuntimeError as e:
        _audit('mail_test_fail', me, request.remote_addr or '', '测试邮件失败: ' + str(e))
        return jsonify({'ok': False, 'msg': str(e)}), 500
    _audit('mail_test', me, request.remote_addr or '', '发送测试邮件到 ' + to)
    return jsonify({'ok': True, 'msg': '测试邮件已发送到 ' + to + '，请查收'})


@app.route('/api/ssrf/config', methods=['GET', 'POST'])
@require_auth
def ssrf_config():
    """插件 SSRF 内网白名单配置（仅超管）：GET 读取，POST 整体覆盖并即时生效。"""
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可配置 SSRF 白名单'}), 403
    if request.method == 'GET':
        cfg = admin.get('ssrf') or {}
        return jsonify({'ok': True, 'allowlist': cfg.get('allowlist') or []})
    data = request.get_json(silent=True) or {}
    allowlist = data.get('allowlist')
    if not isinstance(allowlist, list):
        return jsonify({'ok': False, 'msg': '参数格式错误'}), 400
    import ipaddress
    clean = []
    for item in allowlist:
        s = str(item or '').strip()
        if not s:
            continue
        try:
            ipaddress.ip_network(s, strict=False)
        except ValueError:
            return jsonify({'ok': False, 'msg': '无效网段: ' + s}), 400
        clean.append(s)
    admin['ssrf'] = {'allowlist': clean}
    save_admin(admin)
    # 热更新内存中的白名单，无需重启即生效
    SSRF_ALLOWED_NETS.clear()
    SSRF_ALLOWED_NETS.extend(_load_ssrf_allowlist())
    _audit('ssrf_allowlist_save', me, request.remote_addr or '',
           '更新 SSRF 白名单: ' + (','.join(clean) or '(空)'))
    return jsonify({'ok': True, 'msg': 'SSRF 白名单已保存并即时生效', 'allowlist': clean})


def is_super_admin(admin, username):
    """判断是否为超级管理员。兼容旧配置：无 is_super 字段时，users 中第一个账号视为超管。"""
    if not admin:
        return False
    users = admin.get('users', []) or []
    for u in users:
        if u.get('username') == username:
            if u.get('is_super'):
                return True
            return bool(users and users[0].get('username') == username)
    return False


def _admin_snapshot(admin, me):
    users = admin.get('users', []) if admin else []
    return [{
        'username': u.get('username'),
        'is_super': is_super_admin(admin, u.get('username')),
        'enabled': u.get('enabled', True),
        'created_at': u.get('created_at', ''),
        'email': _mask_email(u.get('email', '')),
        'self': u.get('username') == me,
    } for u in users]


@app.route('/api/admins', methods=['GET', 'POST'])
@require_auth
def admins_manage():
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可管理账号'}), 403
    if request.method == 'GET':
        return jsonify({'ok': True, 'admins': _admin_snapshot(admin, me)})
    data = request.get_json(silent=True) or {}
    new_user = str(data.get('username') or '').strip()
    new_pwd = str(data.get('password') or '')
    new_email = str(data.get('email') or '').strip()
    if not new_user:
        return jsonify({'ok': False, 'msg': '用户名不能为空'}), 400
    if len(new_pwd) < 8:
        return jsonify({'ok': False, 'msg': '密码至少 8 位'}), 400
    if not new_email:
        return jsonify({'ok': False, 'msg': '邮箱不能为空'}), 400
    if not EMAIL_RE.match(new_email):
        return jsonify({'ok': False, 'msg': '邮箱格式不正确'}), 400
    if _email_taken(admin, new_email):
        return jsonify({'ok': False, 'msg': '该邮箱已被其他账号绑定'}), 400
    users = admin.get('users', []) if admin else []
    if any(u['username'] == new_user for u in users):
        return jsonify({'ok': False, 'msg': '用户名已存在'}), 400
    users.append({
        'username': new_user,
        'password_hash': generate_password_hash(new_pwd),
        'is_super': False,
        'created_at': time.strftime('%Y-%m-%d %H:%M:%S'),
        'email': new_email or '',
    })
    save_admin({'users': users})
    _audit('admin_add', me, request.remote_addr or '', '新增管理员: ' + new_user)
    return jsonify({'ok': True, 'msg': '已新增管理员 ' + new_user})


@app.route('/api/admins/<username>/reset-pwd', methods=['POST'])
@require_auth
def admin_reset_pwd(username):
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可重置密码'}), 403
    if username == me:
        return jsonify({'ok': False, 'msg': '不能重置自己的密码，请到「修改密码」页操作'}), 400
    data = request.get_json(silent=True) or {}
    new_pwd = str(data.get('password') or '')
    if len(new_pwd) < 8:
        return jsonify({'ok': False, 'msg': '新密码至少 8 位'}), 400
    user = next((u for u in admin.get('users', []) if u['username'] == username), None)
    if not user:
        return jsonify({'ok': False, 'msg': '账号不存在'}), 404
    user['password_hash'] = generate_password_hash(new_pwd)
    save_admin(admin)
    for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
        SESSION_STORE.pop(t, None)
    _audit('admin_reset_pwd', me, request.remote_addr or '', '重置密码: ' + username)
    return jsonify({'ok': True, 'msg': '已重置 ' + username + ' 的密码，其会话已全部下线'})


@app.route('/api/admins/<username>', methods=['DELETE'])
@require_auth
def admin_delete(username):
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可删除账号'}), 403
    users = admin.get('users', []) if admin else []
    if username == me:
        return jsonify({'ok': False, 'msg': '不能删除当前登录账号'}), 400
    target = next((u for u in users if u['username'] == username), None)
    if not target:
        return jsonify({'ok': False, 'msg': '账号不存在'}), 404
    if is_super_admin(admin, username):
        return jsonify({'ok': False, 'msg': '不能删除超级管理员'}), 400
    if len(users) <= 1:
        return jsonify({'ok': False, 'msg': '至少保留一个管理员账号'}), 400
    users[:] = [u for u in users if u['username'] != username]
    save_admin({'users': users})
    for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
        SESSION_STORE.pop(t, None)
    _audit('admin_delete', me, request.remote_addr or '', '删除管理员: ' + username)
    return jsonify({'ok': True, 'msg': '已删除管理员 ' + username})


@app.route('/api/admins/<username>/toggle', methods=['POST'])
@require_auth
def admin_toggle(username):
    me = request._g_username
    admin = load_admin()
    if not is_super_admin(admin, me):
        return jsonify({'ok': False, 'msg': '仅超级管理员可停用/启用账号'}), 403
    users = admin.get('users', []) if admin else []
    if username == me:
        return jsonify({'ok': False, 'msg': '不能停用当前登录账号'}), 400
    target = next((u for u in users if u['username'] == username), None)
    if not target:
        return jsonify({'ok': False, 'msg': '账号不存在'}), 404
    if is_super_admin(admin, username):
        return jsonify({'ok': False, 'msg': '不能停用超级管理员'}), 400
    cur = target.get('enabled', True)
    target['enabled'] = not cur
    save_admin(admin)
    if not target['enabled']:
        for t in [t for t in SESSION_STORE if SESSION_STORE[t]['username'] == username]:
            _audit('admin_disable', me, request.remote_addr or '', '停用账号: ' + username + '，会话下线')
            SESSION_STORE.pop(t, None)
    else:
        _audit('admin_enable', me, request.remote_addr or '', '启用账号: ' + username)
    return jsonify({'ok': True, 'msg': ('已启用' if target['enabled'] else '已停用') + '管理员 ' + username})


@app.route('/api/bots', methods=['GET'])
@require_auth
def list_bots():
    bots = load_bots()
    return jsonify({'ok': True, 'bots': [_bot_snapshot(b) for b in bots]})


@app.route('/api/bots', methods=['POST'])
@require_auth
def add_bot():
    data = request.get_json(silent=True) or {}
    b = {
        'bot_name': str(data.get('bot_name') or '').strip(),
        'app_id': str(data.get('app_id') or '').strip(),
        'app_secret': str(data.get('app_secret') or '').strip(),
        'backend_url': str(data.get('backend_url') or '').strip(),
        'internal_token': str(data.get('internal_token') or '').strip(),
    }
    err = validate_bot(b)
    if err:
        return jsonify({'ok': False, 'msg': err}), 400
    if not b['app_secret']:
        return jsonify({'ok': False, 'msg': 'app_secret 不能为空'}), 400
    bots = load_bots()
    if any(x['app_id'] == b['app_id'] for x in bots):
        return jsonify({'ok': False, 'msg': '该 AppID 已存在'}), 400
    b['app_secret'] = _encrypt_secret(b['app_secret'])
    bots.append(b)
    save_bots(bots)
    _audit('bot_add', request._g_username, request.remote_addr or '', f"app_id={b['app_id']}")
    return jsonify({'ok': True, 'msg': '已添加，重启网关后生效'})


@app.route('/api/bots/<app_id>', methods=['PUT'])
@require_auth
def edit_bot(app_id):
    data = request.get_json(silent=True) or {}
    bots = load_bots()
    b = next((x for x in bots if x['app_id'] == app_id), None)
    if not b:
        return jsonify({'ok': False, 'msg': '机器人不存在'}), 404
    if 'bot_name' in data:
        b['bot_name'] = str(data['bot_name']).strip()
    if 'backend_url' in data:
        b['backend_url'] = str(data['backend_url']).strip()
    if 'internal_token' in data and str(data['internal_token']).strip():
        b['internal_token'] = str(data['internal_token']).strip()
    secret = str(data.get('app_secret') or '').strip()
    if secret:
        b['app_secret'] = _encrypt_secret(secret)
    err = validate_bot(b)
    if err:
        return jsonify({'ok': False, 'msg': err}), 400
    save_bots(bots)
    _audit('bot_edit', request._g_username, request.remote_addr or '', f"app_id={app_id}")
    return jsonify({'ok': True, 'msg': '已保存，重启网关后生效'})


@app.route('/api/bots/<app_id>', methods=['DELETE'])
@require_auth
def delete_bot(app_id):
    bots = load_bots()
    remain = [x for x in bots if x['app_id'] != app_id]
    if len(remain) == len(bots):
        return jsonify({'ok': False, 'msg': '机器人不存在'}), 404
    save_bots(remain)
    _audit('bot_delete', request._g_username, request.remote_addr or '', f"app_id={app_id}")
    return jsonify({'ok': True, 'msg': '已删除，重启网关后生效'})


@app.route('/api/bots/reload', methods=['POST'])
@require_auth
def reload_bots():
    """配置变更后自拉起新进程再退出（不依赖外部守护，实现干净重载）。"""
    _audit('restart', request._g_username, request.remote_addr or '')
    print('[PANEL] 收到重启请求，将自拉起新进程并退出。', flush=True)
    try:
        script = os.path.abspath(__file__)
        if os.name == 'nt':
            DETACHED_PROCESS = 0x00000008
            CREATE_NEW_PROCESS_GROUP = 0x00000200
            creationflags = DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP
        else:
            creationflags = 0
        subprocess.Popen(
            [sys.executable, script],
            cwd=os.path.dirname(script),
            env=os.environ.copy(),
            creationflags=creationflags,
            close_fds=True,
        )
        print('[PANEL] 新进程已拉起，本进程将退出。', flush=True)
    except Exception as e:
        print('[PANEL] 拉起新进程失败: %s' % e, flush=True)
        return jsonify({'ok': False, 'msg': '重启失败: %s' % e})
    threading.Timer(0.8, lambda: os._exit(0)).start()
    return jsonify({'ok': True, 'msg': '网关正在重启...'})


@app.route('/api/calls', methods=['GET'])
@require_auth
def list_calls():
    limit = min(max(int(request.args.get('limit', 100)), 1), 500)
    filter_appid = (request.args.get('app_id') or '').strip()
    rows = []
    if os.path.exists(CALLS_FILE):
        with open(CALLS_FILE, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    row = json.loads(line)
                    if filter_appid and row.get('app_id') != filter_appid:
                        continue
                    rows.append(row)
                except Exception:
                    continue
    return jsonify({'ok': True, 'calls': rows[-limit:][::-1]})


@app.route('/api/plugins', methods=['GET'])
@require_auth
def api_plugins_list():
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用（缺 plugin_manager 模块）'})
    trust = load_trust()
    plugs = []
    for p in PLUGIN_MGR.snapshot():
        p['trusted'] = bool((trust.get(p['id']) or {}).get('trusted'))
        plugs.append(p)
    return jsonify({'ok': True, 'plugins': plugs})


@app.route('/api/plugins/<pid>/enable', methods=['POST'])
@require_auth
def api_plugin_enable(pid):
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用'})
    rec = PLUGIN_MGR.get(pid)
    if not rec:
        return jsonify({'ok': False, 'msg': '插件不存在'})
    trust = load_trust()
    if not rec['manifest'].get('builtin') and not (trust.get(pid) or {}).get('trusted'):
        return jsonify({'ok': False, 'need_trust': True,
                        'permissions': rec['manifest'].get('permissions') or [],
                        'repository': rec['manifest'].get('repository') or '',
                        'author': rec['manifest'].get('author') or '-',
                        'name': rec['manifest'].get('name') or pid,
                        'msg': '该插件尚未标记信任，请先确认权限后信任并启用'})
    ok, msg = PLUGIN_MGR.set_enabled(pid, True)
    return jsonify({'ok': ok, 'msg': msg or '已启用'})


@app.route('/api/plugins/<pid>/disable', methods=['POST'])
@require_auth
def api_plugin_disable(pid):
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用'})
    ok, msg = PLUGIN_MGR.set_enabled(pid, False)
    return jsonify({'ok': ok, 'msg': msg or '已停用'})


@app.route('/api/plugins/<pid>/reload', methods=['POST'])
@require_auth
def api_plugin_reload(pid):
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用'})
    ok = PLUGIN_MGR.reload(pid)
    return jsonify({'ok': ok, 'msg': '已触发热重载' if ok else '插件不存在'})


@app.route('/api/plugins/<pid>/remove', methods=['POST'])
@require_auth
def api_plugin_remove(pid):
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用'})
    rec = PLUGIN_MGR.get(pid)
    if rec and rec['manifest'].get('builtin'):
        return jsonify({'ok': False, 'msg': '内置插件不可卸载'})
    PLUGIN_MGR.remove(pid, keep_dir=False)
    return jsonify({'ok': True, 'msg': '已卸载'})


@app.route('/api/plugins/trust', methods=['POST'])
@require_auth
def api_plugin_trust():
    body = request.get_json(silent=True) or {}
    pid = (body.get('id') or '').strip()
    trusted = bool(body.get('trusted'))
    if not pid or PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '参数错误'})
    trust = load_trust()
    rec = PLUGIN_MGR.get(pid)
    if rec is None:
        return jsonify({'ok': False, 'msg': '插件不存在'})
    trust[pid] = {'trusted': trusted, 'at': time.strftime('%Y-%m-%d %H:%M:%S'),
                  'name': rec['manifest'].get('name') or pid,
                  'permissions': rec['manifest'].get('permissions') or []}
    save_trust(trust)
    _audit('plugin_trust', pid, 'admin', 'trusted' if trusted else 'untrusted')
    return jsonify({'ok': True, 'msg': '已' + ('信任' if trusted else '取消信任')})


@app.route('/api/plugins/upload', methods=['POST'])
@require_auth
def api_plugin_upload():
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用'})
    f = request.files.get('file')
    if not f or not f.filename.endswith('.zip'):
        return jsonify({'ok': False, 'msg': '请上传 .zip 插件包'})
    ok, msg = PLUGIN_MGR.install_zip(f.read())
    return jsonify({'ok': ok, 'msg': '已安装插件: ' + msg if ok else msg})


@app.route('/api/plugins/github', methods=['POST'])
@require_auth
def api_plugin_github():
    # 从 GitHub 仓库安装：解析仓库地址 → GitHub API 取默认分支 → 下载 zip → 安装
    if PLUGIN_MGR is None:
        return jsonify({'ok': False, 'msg': '插件系统未启用'})
    import re as _re
    import urllib.request
    url = (request.get_json(silent=True) or {}).get('url') or ''
    m = _re.match(r'https?://(?:www\.)?github\.com/([^/]+)/([^/#?]+)', url)
    if not m:
        return jsonify({'ok': False, 'msg': '无法解析 GitHub 仓库地址'})
    owner, repo = m.group(1), m.group(2).rstrip('/')
    api_url = 'https://api.github.com/repos/%s/%s' % (owner, repo)
    try:
        with urllib.request.urlopen(api_url, timeout=15) as resp:
            info = json.loads(resp.read().decode('utf-8', 'replace'))
        default_branch = info.get('default_branch') or 'main'
        dl = 'https://codeload.github.com/%s/%s/zip/refs/heads/%s' % (owner, repo, default_branch)
        with urllib.request.urlopen(dl, timeout=60) as resp:
            data = resp.read()
        ok, msg = PLUGIN_MGR.install_zip(data)
        return jsonify({'ok': ok, 'msg': '已从 GitHub 安装: ' + msg if ok else msg})
    except Exception as e:
        return jsonify({'ok': False, 'msg': 'GitHub 安装失败: %s: %s' % (type(e).__name__, e)})


@app.route('/api/overview', methods=['GET'])
@require_auth
def overview():
    bots = load_bots()
    online = sum(1 for b in bots if _bot_snapshot(b).get('online'))
    return jsonify({'ok': True, 'total': len(bots), 'online': online, 'calls_file': os.path.basename(CALLS_FILE)})


# ================= 前端 =================
ADMIN_HTML = r"""<!DOCTYPE html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<link rel="icon" type="image/png" href="/panel_logo.png">
<title>Mir Dev Studio 网关管理面板</title>
<style>
:root{
  --gold:#9db4ff; --gold-hi:#eef3ff; --gold-deep:#5a6fc0;
  --bg:#0e1116; --ink:#f4f7fb; --ink-dim:#b8c2d4; --line:rgba(157,180,255,.20);
}
*{margin:0;padding:0;box-sizing:border-box}
body{
  font-family:"Microsoft YaHei","PingFang SC",system-ui,sans-serif;
  min-height:100vh; color:var(--ink); font-size:14px; line-height:1.6;
  background:
    radial-gradient(1100px 560px at 12% -8%, rgba(157,180,255,.16), transparent 62%),
    radial-gradient(900px 480px at 96% 112%, rgba(124,106,220,.12), transparent 62%),
    linear-gradient(rgba(8,10,15,.55), rgba(8,10,15,.68)),
    var(--bg);
  -webkit-font-smoothing:antialiased;
}
#gradient-waves{position:fixed;inset:0;width:100%;height:100%;z-index:-1;display:block;pointer-events:none}
.glass{
  background:linear-gradient(158deg, rgba(157,180,255,.10), rgba(255,255,255,.05));
  backdrop-filter:blur(22px) saturate(1.15); -webkit-backdrop-filter:blur(22px) saturate(1.15);
  border:1px solid var(--line);
  border-radius:22px;
  box-shadow:0 28px 70px rgba(0,0,0,.45), inset 0 1px 0 rgba(255,255,255,.09);
}
.modal-overlay{position:fixed;inset:0;display:none;align-items:center;justify-content:center;background:rgba(12,9,24,.50);backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);z-index:999}
.modal-overlay.active{display:flex}
#confirmOverlay{z-index:1000}
#toastWrap{position:fixed;top:18px;right:18px;z-index:1200;display:flex;flex-direction:column;gap:10px;align-items:flex-end;pointer-events:none}
.toast{pointer-events:auto;min-width:220px;max-width:min(360px,86vw);padding:12px 16px;border-radius:12px;background:rgba(20,16,40,.86);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);border:1px solid rgba(157,180,255,.28);box-shadow:0 8px 28px rgba(0,0,0,.35);display:flex;align-items:flex-start;gap:10px;font-size:13px;line-height:1.6;color:var(--ink, #e8e6f2);animation:toastIn .32s cubic-bezier(.2,.9,.3,1.2)}
.toast.out{animation:toastOut .28s ease forwards}
.toast .t-ico{flex:none;width:18px;height:18px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-size:12px;font-weight:700;color:#fff;margin-top:1px}
.toast.ok .t-ico{background:linear-gradient(135deg,#3ddc84,#21b56b)}
.toast.err .t-ico{background:linear-gradient(135deg,#ff6b81,#e8435a)}
.toast.info .t-ico{background:linear-gradient(135deg,#7aa2ff,#5b7cfa)}
.toast.ok{border-color:rgba(61,220,132,.45)}
.toast.err{border-color:rgba(255,107,129,.5)}
@keyframes toastIn{from{opacity:0;transform:translateX(40px)}to{opacity:1;transform:none}}
@keyframes toastOut{to{opacity:0;transform:translateX(40px)}}
.modal{width:min(430px,92vw);padding:26px 26px 22px}
.modal h3{font-size:16px;margin-bottom:8px;color:var(--gold-hi)}
.modal p{font-size:13.5px;color:var(--ink-dim);line-height:1.7}
.modal .modal-actions{display:flex;justify-content:flex-end;gap:10px;margin-top:22px}
/* ===== 登录页 ===== */
#loginView{width:100%;min-height:100vh;display:none;flex-direction:column;align-items:center;justify-content:center;padding:24px}
#loginView.active{display:flex}
#setupView{width:100%;min-height:100vh;display:none;flex-direction:column;align-items:center;justify-content:center;padding:24px}
#setupView.active{display:flex}
#setupView.active .brand{animation:fadeUp .7s cubic-bezier(.22,.9,.3,1) both}
#setupView.active .login-card{animation:popIn .55s cubic-bezier(.2,.9,.3,1.15) .12s both}
.brand{display:flex;align-items:center;gap:14px;margin-bottom:30px}
.brand-mark{
  width:54px;height:54px;border-radius:16px;display:flex;align-items:center;justify-content:center;
  background:linear-gradient(140deg,var(--gold-hi),var(--gold-deep));
  box-shadow:0 10px 28px rgba(157,180,255,.45), inset 0 1px 0 rgba(255,255,255,.40);
  color:#f6f8ff;font-weight:800;font-size:22px;letter-spacing:0;
}
.brand-txt h1{font-size:25px;font-weight:700;letter-spacing:1px;color:var(--gold-hi);line-height:1.2}
.brand-txt p{font-size:12px;color:var(--ink-dim);letter-spacing:2px;margin-top:2px}
.login-card{width:min(392px,94vw);padding:38px 34px 30px}
.login-card h2{font-size:18px;color:var(--ink);margin-bottom:4px}
.login-card .tip{font-size:12px;color:var(--ink-dim);margin-bottom:22px}
.field{margin-bottom:16px}
.field label{display:block;font-size:12.5px;color:var(--ink-dim);margin-bottom:7px;letter-spacing:.5px}
input[type=text],input[type=password],input[type=email]{
  width:100%;padding:12px 14px;border-radius:11px;
  border:1px solid rgba(157,180,255,.28);background:rgba(0,0,0,.30);
  color:var(--ink);font-size:14px;outline:none;transition:border-color .2s, box-shadow .2s;
}
input:focus{border-color:var(--gold);box-shadow:0 0 0 3px rgba(157,180,255,.30)}
.cf-wrap{position:relative;display:inline-block}
.cf-btn{display:inline-flex;align-items:center;gap:8px;padding:8px 14px;border-radius:10px;border:1px solid rgba(255,255,255,.16);background:rgba(255,255,255,.08);color:var(--ink);font-size:13px;outline:none;cursor:pointer;backdrop-filter:blur(6px);-webkit-backdrop-filter:blur(6px);font-family:inherit;transition:background .15s}
.cf-btn:hover{background:rgba(255,255,255,.13)}
.cf-arrow{font-size:10px;opacity:.75;transition:transform .2s}
.cf-wrap.open .cf-arrow{transform:rotate(180deg)}
.cf-menu{position:absolute;top:calc(100% + 6px);left:0;min-width:100%;max-height:260px;overflow:auto;border-radius:12px;border:1px solid rgba(255,255,255,.22);background:rgba(244,246,248,.92);backdrop-filter:blur(14px);-webkit-backdrop-filter:blur(14px);box-shadow:0 12px 32px rgba(10,14,40,.45);padding:6px;display:none;z-index:99}
.cf-menu.open{display:block}
.cf-menu .it{padding:9px 12px;border-radius:8px;color:#1f2328;font-size:13px;cursor:pointer;white-space:nowrap;transition:background .15s}
.cf-menu .it:hover{background:rgba(30,35,40,.08)}
.cf-menu .it.sel{background:rgba(160,168,180,.30);font-weight:600}
.btn{
  display:inline-flex;align-items:center;justify-content:center;gap:6px;
  padding:11px 22px;border-radius:11px;border:none;cursor:pointer;
  background:linear-gradient(135deg,var(--gold-hi),var(--gold-deep));color:#f6f8ff;
  font-weight:700;font-size:14px;letter-spacing:1px;transition:.2s;
  box-shadow:0 8px 24px rgba(90,111,192,.45);
}
.btn:hover{filter:brightness(1.08);transform:translateY(-1px)}
.btn:active{transform:translateY(0)}
.btn.block{width:100%}
.btn.ghost{background:rgba(255,255,255,.07);color:var(--ink);border:1px solid var(--line);box-shadow:none}
.btn.ghost:hover{background:rgba(255,255,255,.12)}
.btn.danger{background:linear-gradient(135deg,#c96a5e,#a34035);color:#fff;box-shadow:0 8px 22px rgba(180,70,55,.25)}
.btn.sm{padding:6px 13px;font-size:12px;border-radius:9px}
.msg{font-size:12.5px;min-height:18px;margin-top:12px}
.msg.err{color:#e28a78}.msg.ok{color:#8fd6a0}
/* ===== 主界面 ===== */
#mainView{display:none;max-width:1080px;margin:0 auto;padding:26px 22px 60px}
#mainView.active{display:block}
.app-header{display:flex;align-items:center;justify-content:space-between;gap:16px;margin-bottom:22px}
.app-header .brand{margin:0}
.app-header .brand-mark{width:44px;height:44px;border-radius:13px;font-size:18px}
.app-header .brand-txt h1{font-size:20px}
.user-box{display:flex;align-items:center;gap:12px;font-size:13px;color:var(--ink-dim)}
.user-box b{color:var(--gold-hi);font-weight:600}
.card{padding:22px 24px;margin-bottom:18px}
.card-hd{display:flex;align-items:center;justify-content:space-between;gap:12px;margin-bottom:16px}
.card-hd h3{font-size:16px;color:var(--gold-hi);font-weight:600;letter-spacing:.5px}
.card-hd .note{font-size:12px;color:var(--ink-dim)}
.tabs{display:flex;gap:8px;margin-bottom:18px;flex-wrap:wrap}
.tab{
  padding:8px 20px;border-radius:999px;border:1px solid var(--line);
  background:rgba(255,255,255,.04);color:var(--ink-dim);font-size:13.5px;cursor:pointer;transition:.2s;
}
.tab:hover{color:var(--ink);border-color:var(--gold)}
.tab.active{background:linear-gradient(135deg,var(--gold-hi),var(--gold-deep));color:#f6f8ff;font-weight:700;border-color:transparent}
.tabPage{display:none}.tabPage.active{display:block}
table{width:100%;border-collapse:collapse;font-size:13.5px}
th{text-align:left;padding:10px 10px;color:#ffffff;font-weight:700;font-size:12px;letter-spacing:1px;border-bottom:1px solid var(--line)}
td{padding:11px 10px;border-bottom:1px solid rgba(255,255,255,.06);vertical-align:middle}
tr:hover td{background:rgba(255,255,255,.03)}
.mono{font-family:Consolas,"Courier New",monospace;font-size:12px;color:#e8ebef}
.dot{display:inline-block;width:9px;height:9px;border-radius:50%;margin-right:7px;vertical-align:1px}
.dot.on{background:#62c97f;box-shadow:0 0 8px rgba(98,201,127,.7)}
.dot.off{background:#c65b4a;box-shadow:0 0 8px rgba(198,91,74,.55)}
input::placeholder{color:rgba(255,255,255,.5)}
.empty{color:#aeb4bd;text-align:center;padding:26px 0}
.grid-add{display:grid;grid-template-columns:repeat(auto-fit,minmax(190px,1fr));gap:12px;align-items:end}
.grid-add .field{margin:0}
.stat-row{display:flex;gap:18px;flex-wrap:wrap}
.stat{flex:1;min-width:150px;padding:16px 18px;border-radius:14px;border:1px solid var(--line);background:rgba(255,255,255,.03)}
.stat b{display:block;font-size:26px;color:var(--gold-hi);font-weight:700;line-height:1.2}
.stat span{font-size:12px;color:var(--ink-dim)}
@media(max-width:720px){ .app-header{flex-direction:column;align-items:flex-start} }
.footer-copy{position:fixed;right:20px;bottom:14px;z-index:60;font-size:11.5px;letter-spacing:.6px;color:rgba(255,255,255,.75);pointer-events:none;user-select:none;text-shadow:0 1px 5px rgba(0,0,0,.55)}

/* ===== UI 动效增强 ===== */
@keyframes fadeUp{from{opacity:0;transform:translateY(14px)}to{opacity:1;transform:none}}
@keyframes popIn{from{opacity:0;transform:scale(.93) translateY(8px)}to{opacity:1;transform:none}}
@keyframes fadeIn{from{opacity:0}to{opacity:1}}
@keyframes shine{0%{background-position:130% 0;opacity:0}12%{opacity:1}100%{background-position:-60% 0;opacity:0}}
@keyframes dotBreath{0%,100%{transform:scale(1);opacity:1}50%{transform:scale(1.45);opacity:.6}}

/* 登录页入场 */
#loginView.active .brand{animation:fadeUp .7s cubic-bezier(.22,.9,.3,1) both}
#loginView.active .login-card{animation:popIn .55s cubic-bezier(.2,.9,.3,1.15) .12s both}

/* 主界面入场：头部与卡片错峰上浮 */
#mainView.active .app-header{animation:fadeUp .5s ease both}
#mainView.active .card{animation:fadeUp .5s ease both}
#mainView.active .card:nth-child(2){animation-delay:.06s}
#mainView.active .card:nth-child(3){animation-delay:.12s}
#mainView.active .card:nth-child(4){animation-delay:.18s}
#mainView.active .card:nth-child(5){animation-delay:.24s}

/* 页签切换淡入 */
.tabPage.active{animation:fadeUp .38s ease both}

/* 弹窗弹出 */
.modal-overlay.active{animation:fadeIn .18s ease both}
.modal-overlay.active .modal{animation:popIn .3s cubic-bezier(.2,.9,.3,1.18) both}

/* 卡片悬浮：上浮 + 蓝紫光晕边框 */
.card{transition:transform .28s cubic-bezier(.2,.9,.3,1),box-shadow .28s ease,border-color .28s ease}
.card:hover{transform:translateY(-3px);border-color:rgba(157,180,255,.5);box-shadow:0 30px 70px rgba(0,0,0,.55),0 0 0 1px rgba(157,180,255,.16),0 0 26px rgba(157,180,255,.14),inset 0 1px 0 rgba(255,255,255,.12)}

/* 统计卡悬浮 */
.stat{transition:transform .25s ease,border-color .25s ease,background .25s ease}
.stat:hover{transform:translateY(-2px);border-color:rgba(157,180,255,.55);background:rgba(157,180,255,.08)}

/* 主按钮：扫光 + 微放大 */
.btn{position:relative;overflow:hidden;transition:transform .18s ease,box-shadow .25s ease,filter .25s ease}
.btn:hover{transform:translateY(-1px) scale(1.015)}
.btn::after{content:"";position:absolute;inset:0;border-radius:inherit;background:linear-gradient(110deg,transparent 30%,rgba(255,255,255,.38) 50%,transparent 70%);background-size:220% 100%;background-position:130% 0;opacity:0;pointer-events:none}
.btn:hover::after{animation:shine .85s ease .04s forwards}

/* 页签悬浮微浮 */
.tab{transition:transform .18s ease,border-color .2s ease,color .2s ease}
.tab:hover{transform:translateY(-1px)}

/* 状态点呼吸 */
.dot.on,.dot.off{animation:dotBreath 2.4s ease-in-out infinite}
.dot.off{animation-duration:3.2s}

/* 品牌徽标悬浮微光 */
.brand-mark{transition:transform .3s ease,box-shadow .3s ease}
.brand-mark:hover{transform:translateY(-2px) scale(1.03);box-shadow:0 14px 34px rgba(157,180,255,.55),inset 0 1px 0 rgba(255,255,255,.4)}

/* 表格行 hover 高亮提亮 */
tr:hover td{background:rgba(157,180,255,.07)}
</style>
</head>
<body>

<canvas id="gradient-waves"></canvas>

<!-- ===== 登录 ===== -->
<!-- ===== 首次安装向导 ===== -->
<div id="setupView">
  <div class="brand">
    <div class="brand-mark" style="background:url('/panel_logo.png') center/cover no-repeat;color:transparent">MD</div>
    <div class="brand-txt">
      <h1>网关管理面板</h1>
      <p>Mir Dev Studio BOT GATEWAY</p>
    </div>
  </div>
  <div class="login-card glass">
    <h2>首次初始化</h2>
    <div class="tip">检测到系统尚未创建管理员，请设置初始超级管理员账号（保存后请牢记，用于登录与找回密码）。</div>
    <div class="field"><label>管理员用户名</label><input type="text" id="setupUser" autocomplete="off" maxlength="24"></div>
    <div class="field"><label>登录密码（至少 8 位）</label><input type="password" id="setupPass" autocomplete="new-password"></div>
    <div class="field"><label>确认密码</label><input type="password" id="setupPass2" autocomplete="new-password" onkeydown="if(event.key==='Enter')doSetup()"></div>
    <div class="field"><label>管理邮箱（用于找回密码）</label><input type="email" id="setupEmail" autocomplete="email"></div>
    <button class="btn block" id="setupBtn" onclick="doSetup()">创建管理员</button>
  </div>
</div>

<div id="loginView">
  <div class="brand">
    <div class="brand-mark" style="background:url('/panel_logo.png') center/cover no-repeat;color:transparent">MD</div>
    <div class="brand-txt">
      <h1>网关管理面板</h1>
      <p>Mir Dev Studio BOT GATEWAY</p>
    </div>
  </div>
  <div class="login-card glass">
    <h2>欢迎回来</h2>
    <div class="tip">请使用运维管理员账号登录</div>
    <div class="field">
      <label>用户名</label>
      <input type="text" id="username" autocomplete="username">
    </div>
    <div class="field">
      <label>密码</label>
      <input type="password" id="password" autocomplete="current-password" onkeydown="if(event.key==='Enter')doLogin()">
    </div>
    <div style="text-align:right;margin:-4px 0 14px"><a href="javascript:void(0)" onclick="showForgot()" style="color:var(--ink-dim);font-size:12px;text-decoration:none">忘记密码？</a></div>
    <button class="btn block" onclick="doLogin()">登 录</button>
    <div id="loginMsg" class="msg err"></div>
  </div>
</div>

<!-- ===== 主界面 ===== -->
<div id="mainView">
  <div class="app-header">
    <div class="brand">
      <div class="brand-mark" style="background:url('/panel_logo.png') center/cover no-repeat;color:transparent">MD</div>
      <div class="brand-txt">
        <h1>网关管理面板</h1>
        <p>Mir Dev Studio BOT GATEWAY</p>
      </div>
    </div>
    <div class="user-box">
      <span>登录用户：<b id="userTag">-</b></span>
      <button class="btn ghost sm" onclick="logout()">退出登录</button>
    </div>
  </div>

  <div class="tabs">
    <button class="tab active" data-tab="bots">机器人管理</button>
    <button class="tab" data-tab="logs">调用日志</button>
    <button class="tab" data-tab="sessions">登录会话</button>
    <button class="tab" data-tab="plugins" id="tabBtnPlugins" style="display:none">插件管理</button>
    <button class="tab" data-tab="system" id="tabBtnSystem">系统设置</button>
  </div>

  <!-- 机器人管理 -->
  <div id="tab-bots" class="tabPage active">
    <div class="card glass">
      <div class="stat-row" style="margin-bottom:4px">
        <div class="stat"><b id="stTotal">0</b><span>机器人总数</span></div>
        <div class="stat"><b id="stOnline">0</b><span>当前在线</span></div>
        <div class="stat"><b id="stCalls">0</b><span>日志文件</span></div>
      </div>
    </div>
    <div class="card glass">
      <div class="card-hd">
        <h3>机器人列表</h3>
        <div>
          <button class="btn ghost sm" onclick="loadBots()">刷新</button>
          <button class="btn sm" onclick="restartGateway()" style="margin-left:8px">重启网关</button>
        </div>
      </div>
      <table>
        <thead><tr><th>名称</th><th>AppID</th><th>后端地址</th><th>状态</th><th>心跳</th><th>操作</th></tr></thead>
        <tbody id="botRows"></tbody>
      </table>
    </div>
    <div class="card glass">
      <div class="card-hd"><h3>新增机器人</h3><span class="note">AppSecret 将自动加密存储</span></div>
      <div class="grid-add">
        <div class="field"><label>机器人名称</label><input type="text" id="n_name" placeholder="如 评审助手"></div>
        <div class="field"><label>AppID</label><input type="text" id="n_appid" placeholder="QQ开放平台AppID"></div>
        <div class="field"><label>AppSecret</label><input type="text" id="n_secret" placeholder="应用密钥"></div>
        <div class="field"><label>backend_url</label><input type="text" id="n_url" placeholder="http://127.0.0.1:7001"></div>
        <div class="field"><label>internal_token（≥8位）</label><input type="text" id="n_token" placeholder="X-Service-Token"></div>
        <div><button class="btn block" onclick="addBot()">添加机器人</button></div>
      </div>
      <div id="botMsg" class="msg"></div>
    </div>
  </div>

  <!-- 调用日志 -->
  <div id="tab-logs" class="tabPage">
    <div class="card glass">
      <div class="card-hd">
        <h3>调用日志</h3>
        <div class="cf-wrap" id="cfWrap">
          <button type="button" class="cf-btn" onclick="toggleCf()"><span id="cfLabel">全部机器人</span><span class="cf-arrow">▾</span></button>
          <div class="cf-menu" id="cfMenu"></div>
        </div>
        <button class="btn ghost sm" onclick="loadCalls()">刷新</button>
      </div>
      <table>
        <thead><tr><th>时间</th><th>AppID</th><th>类型</th><th>参数</th><th>结果</th><th>备注</th></tr></thead>
        <tbody id="callRows"></tbody>
      </table>
    </div>
  </div>

  <!-- 登录会话 -->
  <div id="tab-sessions" class="tabPage">
    <div class="card glass">
      <div class="card-hd">
        <h3>登录会话</h3>
        <button class="btn danger sm" onclick="killOthers()">下线其他设备</button>
      </div>
      <p class="note" style="margin-bottom:14px">当前账号采用单活跃会话机制：新设备登录将自动踢掉旧设备。</p>
      <table>
        <thead><tr><th>会话</th><th>登录 IP</th><th>登录时间</th><th>过期时间</th><th>当前</th></tr></thead>
        <tbody id="sessionRows"></tbody>
      </table>
    </div>
  </div>

  <!-- 系统设置 -->
  <div id="tab-system" class="tabPage">
    <div id="sysSuperBox" style="display:none">
    <!-- 管理员管理（仅超管） -->
    <div id="sys-admins">
    <div class="card glass">
      <div class="card-hd"><h3>管理员列表</h3><button class="btn ghost sm" onclick="loadAdmins()">刷新</button></div>
      <table>
        <thead><tr><th>用户名</th><th>角色</th><th>绑定邮箱</th><th>创建时间</th><th>操作</th></tr></thead>
        <tbody id="adminRows"></tbody>
      </table>
    </div>
    <div class="card glass">
      <div class="card-hd"><h3>新增管理员</h3><span class="note">新账号拥有完整面板权限</span></div>
      <div class="grid-add">
        <div class="field"><label>用户名</label><input type="text" id="a_name" placeholder="登录用户名"></div>
        <div class="field"><label>初始密码（≥8位）</label><input type="password" id="a_pwd" placeholder="初始密码"></div>
        <div class="field"><label>邮箱（必填）</label><input type="email" id="a_email" placeholder="用于找回密码" required></div>
        <div><button class="btn block" onclick="addAdmin()">添加管理员</button></div>
      </div>
      <div id="admMsg" class="msg"></div>
    </div>
  </div>
  </div>

    <!-- 账号安全（所有管理员） -->
    <div id="sys-account">
    <div class="card glass">
      <div class="card-hd"><h3>修改密码</h3></div>
      <div class="field"><label>原密码</label><input type="password" id="p_old"></div>
      <div class="field"><label>新密码（至少 8 位）</label><input type="password" id="p_new"></div>
      <button class="btn" onclick="changePwd()">确认修改</button>
      <div id="pwdMsg" class="msg"></div>
    </div>
    <div class="card glass">
      <div class="card-hd"><h3>邮箱绑定</h3><span class="note">绑定后可用于忘记密码时找回</span></div>
      <div id="mailBindBox">
        <div class="field"><label id="m_email_label">绑定邮箱</label><input type="text" id="m_email" placeholder="name@example.com"></div>
        <div class="field" id="m_codeField" style="display:none"><label>邮箱验证码</label><input type="text" id="m_code" placeholder="6 位验证码"></div>
        <div id="mBindMsg" class="msg"></div>
        <div style="display:flex;gap:10px;flex-wrap:wrap">
          <button class="btn sm" id="mBindBtn" onclick="mBindAction()">发送绑定验证码</button>
          <button class="btn ghost sm" id="mUnbindBtn" style="display:none" onclick="mUnbindStart()">解绑邮箱</button>
          <button class="btn ghost sm" onclick="loadAccount()">刷新</button>
        </div>
      </div>
    </div>
  </div>

    <!-- 邮件服务（仅超管） -->
    <div id="sys-mail" style="display:none">
    <div class="card glass">
      <div class="card-hd"><h3>SMTP 邮件服务</h3><span class="note">用于发送绑定验证码 / 找回密码邮件</span></div>
      <div class="grid-add" style="grid-template-columns:1fr 1fr">
        <div class="field"><label>SMTP 服务器</label><input type="text" id="smtp_host" placeholder="smtp.qq.com"></div>
        <div class="field"><label>端口</label><input type="text" id="smtp_port" placeholder="465"></div>
      </div>
      <div class="field"><label>登录账号</label><input type="text" id="smtp_user" placeholder="发件邮箱账号"></div>
      <div class="field"><label>密码 / 授权码</label><input type="password" id="smtp_pwd" placeholder="留空则保持原密码不变"></div>
      <div class="field"><label>发件人地址</label><input type="text" id="smtp_from" placeholder="留空则使用登录账号"></div>
      <div class="field"><label>发件人名称</label><input type="text" id="smtp_fromname" placeholder="如 网关管理面板"></div>
      <div class="field"><label style="display:flex;align-items:center;gap:8px;cursor:pointer"><input type="checkbox" id="smtp_ssl" checked style="width:auto"> 使用 SSL 加密（465 端口）</label></div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:6px">
        <button class="btn" onclick="saveMailConfig()">保存配置</button>
        <button class="btn ghost" onclick="loadMailConfig()">刷新</button>
      </div>
      <div id="mailMsg" class="msg"></div>
      <div class="field" style="margin-top:14px"><label>测试收件邮箱</label><input type="text" id="smtp_testto" placeholder="test@example.com"></div>
      <button class="btn ghost" onclick="testMail()">发送测试邮件</button>
      <div id="mailTestMsg" class="msg"></div>
    </div>
  </div>

    <!-- SSRF 内网白名单（仅超管） -->
    <div id="sys-ssrf" style="display:none">
    <div class="card glass">
      <div class="card-hd"><h3>插件 SSRF 内网白名单</h3><span class="note">仅超管 · 即改即生效</span></div>
      <div class="note" style="margin-bottom:10px">插件经 host.http_request 访问公网不受影响；仅在确有合法需求时放行本机/内网地址段。未列入白名单的内网、环回、云 metadata 地址仍会被拦截。</div>
      <div style="display:flex;gap:10px;flex-wrap:wrap;margin-bottom:12px">
        <input type="text" id="ssrf_cidr" placeholder="如 127.0.0.1/32，多个网段逐个添加" style="flex:1;min-width:220px">
        <button class="btn" onclick="addSsrf()">添加网段</button>
        <button class="btn ghost" onclick="loadSsrfConfig()">刷新</button>
      </div>
      <div id="ssrfList" style="display:flex;flex-wrap:wrap;gap:8px"></div>
      <div id="ssrfMsg" class="msg"></div>
    </div>
  </div>
  </div>

  <!-- 插件管理 -->
  <div id="tab-plugins" class="tabPage">
    <div class="card glass">
      <div class="card-hd">
        <h3>插件库</h3>
        <div>
          <button class="btn ghost sm" onclick="loadPlugins()">刷新</button>
          <button class="btn sm" onclick="uploadPlugin()" style="margin-left:8px">上传插件包</button>
          <button class="btn ghost sm" onclick="installGithub()" style="margin-left:8px">从 GitHub 安装</button>
        </div>
      </div>
      <div style="overflow:auto">
      <table>
        <thead><tr><th>插件</th><th>版本</th><th>作者</th><th>权限</th><th>状态</th><th>信任</th><th>操作</th></tr></thead>
        <tbody id="pluginRows"></tbody>
      </table>
      </div>
      <input type="file" id="pluginFile" accept=".zip" style="display:none">
      <div id="plugMsg" class="msg"></div>
    </div>
  </div>
</div>

<div id="confirmOverlay" class="modal-overlay">
  <div class="modal glass">
    <h3 id="cfTitle">提示</h3>
    <p id="cfMsg"></p>
    <div class="modal-actions">
      <button class="btn ghost sm" onclick="cfCancel()">取消</button>
      <button class="btn sm" onclick="cfOk()">确认</button>
    </div>
  </div>
</div>
<div id="resetPwdOverlay" class="modal-overlay">
  <div class="modal glass">
    <h3>重置密码</h3>
    <p id="rpTarget" class="note" style="margin-bottom:12px"></p>
    <div class="field"><label>新密码（至少 8 位）</label><input type="password" id="rp_new"></div>
    <div class="modal-actions">
      <button class="btn ghost sm" onclick="rpCancel()">取消</button>
      <button class="btn sm" onclick="rpSave()">确认重置</button>
    </div>
  </div>
</div>
<div id="forgotOverlay" class="modal-overlay">
  <div class="modal glass">
    <h3>找回密码</h3>
    <p class="note" style="margin-bottom:12px">通过绑定的邮箱重置密码，验证码 10 分钟内有效。</p>
    <div class="field"><label>用户名</label><input type="text" id="fg_user"></div>
    <div class="field"><label>绑定邮箱</label><input type="text" id="fg_email"></div>
    <div class="field" id="fgStep2" style="display:none">
      <label>邮箱验证码</label><input type="text" id="fg_code" placeholder="6 位验证码">
      <div style="height:14px"></div>
      <label>新密码（至少 8 位）</label><input type="password" id="fg_pwd">
    </div>
    <div id="fgMsg" class="msg"></div>
    <div class="modal-actions">
      <button class="btn ghost sm" onclick="fgClose()">关闭</button>
      <button class="btn sm" id="fgNext" onclick="fgStep1()">发送验证码</button>
      <button class="btn sm" id="fgSubmit" style="display:none" onclick="fgStep2()">重置密码</button>
    </div>
  </div>
</div>
<div id="unbindOverlay" class="modal-overlay">
  <div class="modal glass">
    <h3>解绑邮箱</h3>
    <p id="ubTarget" class="note" style="margin-bottom:12px"></p>
    <div class="field"><label>邮箱验证码</label><input type="text" id="ub_code" placeholder="6 位验证码"></div>
    <div id="ubMsg" class="msg"></div>
    <div class="modal-actions">
      <button class="btn ghost sm" onclick="ubCancel()">取消</button>
      <button class="btn sm" onclick="ubSave()">确认解绑</button>
    </div>
  </div>
</div>
<div id="editOverlay" class="modal-overlay">
  <div class="modal glass">
    <h3>编辑机器人</h3>
    <div class="field"><label>backend_url（留空不改）</label><input type="text" id="e_url" placeholder="http://127.0.0.1:7001"></div>
    <div class="field"><label>internal_token（留空不改，≥8位）</label><input type="text" id="e_token" placeholder="internal_token"></div>
    <div class="field"><label>AppSecret（留空不改，自动加密）</label><input type="password" id="e_secret" placeholder="AppSecret"></div>
    <div class="modal-actions">
      <button class="btn ghost sm" onclick="eCancel()">取消</button>
      <button class="btn sm" onclick="eSave()">保存修改</button>
    </div>
  </div>
</div>

<script>
let TOKEN = localStorage.getItem('gw_token') || '';
let IS_SUPER = localStorage.getItem('gw_is_super') === '1';
const $ = id => document.getElementById(id);
const hdr = () => ({ 'Content-Type':'application/json', 'Authorization':'Bearer '+TOKEN });

function showLogin(){ $('loginView').classList.add('active'); $('mainView').classList.remove('active'); }
function showMain(){ $('loginView').classList.remove('active'); $('mainView').classList.add('active'); }

let _cfCb=null, _eAppid=null;
let SSRF_CACHE = [];
function showToast(msg, type){
  if(!msg) return;
  var w=$('toastWrap');
  var t=document.createElement('div');
  t.className='toast '+(type==='err'?'err':(type==='ok'?'ok':'info'));
  var ico=document.createElement('span'); ico.className='t-ico';
  ico.textContent = type==='err'?'×':(type==='ok'?'✓':'i');
  var txt=document.createElement('span'); txt.textContent=msg;
  t.appendChild(ico); t.appendChild(txt);
  w.appendChild(t);
  setTimeout(function(){ t.classList.add('out'); setTimeout(function(){ if(t.parentNode) t.parentNode.removeChild(t); }, 300); }, 3200);
}
function showConfirm(title,msg,cb){ $('cfTitle').textContent=title; $('cfMsg').textContent=msg; _cfCb=cb; $('confirmOverlay').classList.add('active'); }
function cfCancel(){ $('confirmOverlay').classList.remove('active'); _cfCb=null; }
function cfOk(){ $('confirmOverlay').classList.remove('active'); var cb=_cfCb; _cfCb=null; if(cb) cb(); }
function eCancel(){ $('editOverlay').classList.remove('active'); _eAppid=null; }
async function eSave(){
  var appid=_eAppid; if(!appid) return;
  var body={}, url=$('e_url').value.trim(), token=$('e_token').value.trim(), secret=$('e_secret').value.trim();
  if(url) body.backend_url=url;
  if(token) body.internal_token=token;
  if(secret) body.app_secret=secret;
  if(!Object.keys(body).length){ showToast('未填写任何修改项','err'); return; }
  showConfirm('保存修改','确认提交该机器人的修改？', async function(){
    var d=await api('/api/bots/'+appid,'PUT',body);
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ loadBots(); eCancel(); }
  });
}

async function api(path, method='GET', body=null){
  const opt = { method, headers:hdr() };
  if(body) opt.body = JSON.stringify(body);
  const res = await fetch(path, opt);
  if(res.status === 401){ TOKEN=''; localStorage.removeItem('gw_token'); showLogin(); throw new Error('会话已过期'); }
  return res.json();
}

async function doLogin(){
  const u = $('username').value.trim(), p = $('password').value;
  if(!u || !p){ showToast('请输入用户名和密码','err'); return; }
  const res = await fetch('/api/login', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({username:u,password:p}) });
  const d = await res.json();
  if(d.ok){ TOKEN = d.token; localStorage.setItem('gw_token', TOKEN); IS_SUPER = !!d.is_super; localStorage.setItem('gw_is_super', IS_SUPER?'1':''); $('userTag').textContent = d.username; applyRoleUI(); showMain(); init(); }
  else { showToast(d.msg || '登录失败','err'); }
}

async function logout(){
  showConfirm('退出登录','确认退出当前登录？', async function(){
    try{ await api('/api/logout','POST'); }catch(e){}
    TOKEN=''; localStorage.removeItem('gw_token'); showLogin();
  });
}

const CF = { cur:'' };
function toggleCf(){
  const m = $('cfMenu'), w = $('cfWrap');
  if(!m || !w) return;
  m.classList.toggle('open'); w.classList.toggle('open');
}
function pickCf(v, n){
  CF.cur = v; $('cfLabel').textContent = n;
  $('cfMenu').classList.remove('open'); $('cfWrap').classList.remove('open');
  loadCalls();
}
document.addEventListener('click', function(e){
  const m = $('cfMenu');
  if(!m || !m.classList.contains('open')) return;
  if(!e.target.closest('.cf-wrap')){ m.classList.remove('open'); $('cfWrap').classList.remove('open'); }
});
function fillCallFilter(appids){
  const m = $('cfMenu'); if(!m) return;
  if(CF.cur && !appids.includes(CF.cur)) CF.cur = '';
  const opts = [{v:'', n:'全部机器人'}].concat(appids.map(a=>({v:a, n:a})));
  m.innerHTML = opts.map(o => '<div class="it' + (o.v===CF.cur?' sel':'') + '" onclick="pickCf(\'' + o.v + '\',\'' + o.n + '\')">' + o.n + '</div>').join('');
  $('cfLabel').textContent = (opts.find(o => o.v===CF.cur) || opts[0]).n;
}

async function loadBots(){
  try{
    const d = await api('/api/bots');
    const rows = (d.bots||[]).map(b => `
      <tr>
        <td>${b.bot_name}</td>
        <td class="mono">${b.app_id}</td>
        <td class="mono">${b.backend_url}</td>
        <td><span class="dot ${b.online?'on':'off'}"></span>${b.online?'在线':'离线'}</td>
        <td class="mono">${b.last_heartbeat||'-'}</td>
        <td>
          <button class="btn ghost sm" onclick="editBot('${b.app_id}')">编辑</button>
          <button class="btn danger sm" onclick="delBot('${b.app_id}')">删除</button>
        </td>
      </tr>`).join('');
    $('botRows').innerHTML = rows || '<tr><td colspan="6" class="empty">暂无机器人，请在下方添加</td></tr>';
    fillCallFilter((d.bots||[]).map(b=>b.app_id));
    loadOverview();
  }catch(e){}
}

async function loadOverview(){
  try{
    const d = await api('/api/overview');
    $('stTotal').textContent = d.total; $('stOnline').textContent = d.online; $('stCalls').textContent = d.calls_file;
  }catch(e){}
}

async function addBot(){
  const body = { bot_name:$('n_name').value.trim(), app_id:$('n_appid').value.trim(),
    app_secret:$('n_secret').value.trim(), backend_url:$('n_url').value.trim(), internal_token:$('n_token').value.trim() };
  if(!body.bot_name || !body.app_id || !body.app_secret || !body.backend_url){
    showToast('请完整填写 名称 / AppID / AppSecret / backend_url','err'); return;
  }
  showConfirm('新增机器人','确认添加该机器人？添加后需重启网关生效。', async function(){
    const d = await api('/api/bots','POST',body);
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ ['n_name','n_appid','n_secret','n_url','n_token'].forEach(i=>$(i).value=''); loadBots(); }
  });
}

async function editBot(appid){
  _eAppid = appid; $('e_url').value=''; $('e_token').value=''; $('e_secret').value='';
  $('editOverlay').classList.add('active');
}

async function delBot(appid){
  showConfirm('删除机器人','确认删除该机器人？删除后需重启网关生效。', async function(){
    const d = await api('/api/bots/'+appid,'DELETE');
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok) loadBots();
  });
}

async function restartGateway(){
  showConfirm('重启网关','重启网关将断开所有 QQ 机器人连接，由守护进程自动拉起。确认重启？', async function(){
    const d = await api('/api/bots/reload','POST');
    showToast(d.msg, d.ok?'ok':'err');
  });
}

async function loadCalls(){
  try{
    const fid = (typeof CF !== 'undefined' && CF.cur) ? CF.cur : '';
    const d = await api('/api/calls' + (fid? '?app_id='+encodeURIComponent(fid) : ''));
    const kindMap = {ticket_id:'工单', email:'邮箱', qq:'QQ'};
    $('callRows').innerHTML = (d.calls||[]).map(c => `
      <tr>
        <td class="mono">${c.ts}</td><td class="mono">${c.app_id}</td>
        <td>${kindMap[c.kind]||c.kind}</td><td class="mono">${c.param}</td>
        <td style="color:${c.ok?'#8fd6a0':'#e28a78'}">${c.ok?'成功':'失败'}</td>
        <td>${c.note||''}</td>
      </tr>`).join('') || '<tr><td colspan="6" class="empty">暂无记录</td></tr>';
  }catch(e){}
}

async function loadSessions(){
  try{
    const d = await api('/api/sessions');
    $('sessionRows').innerHTML = (d.sessions||[]).map(s => `
      <tr>
        <td class="mono">${s.token}</td><td class="mono">${s.ip}</td>
        <td class="mono">${s.created_at}</td><td class="mono">${s.expires_at}</td>
        <td style="color:${s.current?'#ddbdf4':'#8a80a5'}">${s.current?'当前设备':''}</td>
      </tr>`).join('') || '<tr><td colspan="5" class="empty">无活跃会话</td></tr>';
  }catch(e){}
}

async function killOthers(){
  showConfirm('下线其他设备','将强制下线其他设备的登录会话，确认？', async function(){
    await api('/api/sessions/kill-others','POST');
    loadSessions();
  });
}

async function changePwd(){
  const oldP=$('p_old').value, newP=$('p_new').value;
  if(!oldP || !newP){ showToast('请填写旧密码和新密码','err'); return; }
  showConfirm('修改密码','确认修改登录密码？修改后所有设备将重新登录。', async function(){
    const d = await api('/api/password','POST',{ old_pwd:oldP, new_pwd:newP });
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ TOKEN=''; localStorage.removeItem('gw_token'); showLogin(); }
  });
}

// ---- 找回密码（登录页） ----
let _fgUser='', _fgEmail='';
function showForgot(){
  _fgUser=''; _fgEmail='';
  ['fg_user','fg_email','fg_code','fg_pwd'].forEach(i=>$('fg_'+i.split('_')[1]).value='');
  $('fgMsg').textContent=''; $('fgMsg').className='msg';
  $('fgStep2').style.display='none'; $('fgNext').style.display=''; $('fgSubmit').style.display='none';
  $('forgotOverlay').classList.add('active');
}
function fgClose(){ $('forgotOverlay').classList.remove('active'); }
async function fgStep1(){
  const u=$('fg_user').value.trim(), em=$('fg_email').value.trim();
  if(!u || !em){ showToast('请输入用户名和绑定邮箱','err'); return; }
  const d = await fetch('/api/password/forgot',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:u,email:em})}).then(r=>r.json());
  showToast(d.msg, d.ok?'ok':'err');
  if(d.ok){ _fgUser=u; _fgEmail=em; $('fgStep2').style.display=''; $('fgNext').style.display='none'; $('fgSubmit').style.display=''; }
}
async function fgStep2(){
  const code=$('fg_code').value.trim(), pwd=$('fg_pwd').value;
  if(!code || !pwd){ showToast('请输入验证码和新密码','err'); return; }
  const d = await fetch('/api/password/reset',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({username:_fgUser,email:_fgEmail,code:code,password:pwd})}).then(r=>r.json());
  showToast(d.msg, d.ok?'ok':'err');
  if(d.ok){ setTimeout(function(){ fgClose(); $('username').value=_fgUser; $('password').focus(); }, 900); }
}

// ---- 邮箱绑定 ----
let _mBindEmail='', _mBindStep='idle';
async function loadAccount(){
  try{
    const d = await api('/api/account');
    const em = d.email||'';
    $('m_email').value = em;
    $('m_code').value=''; $('m_codeField').style.display='none'; _mBindStep='idle';
    $('mBindMsg').className='msg'; $('mBindMsg').textContent='';
    if(em){
      $('mBindBtn').style.display='none'; $('mUnbindBtn').style.display='';
      $('m_email').readOnly=true;
      $('m_email_label').textContent='已绑定邮箱';
    }else{
      $('mBindBtn').style.display=''; $('mUnbindBtn').style.display='none';
      $('m_email').readOnly=false; $('mBindBtn').textContent='发送绑定验证码';
      $('m_email_label').textContent='绑定邮箱';
      if(!d.smtp_configured){ showToast('系统未配置邮件服务，无法发送绑定验证码','err'); }
    }
  }catch(e){}
}
async function mBindAction(){ return _mBindStep==='idle' ? mBindStart() : mBindVerify(); }
async function mBindStart(){
  const em=$('m_email').value.trim();
  if(!em){ showToast('请输入要绑定的邮箱','err'); return; }
  const d = await api('/api/account/email','POST',{email:em});
  showToast(d.msg, d.ok?'ok':'err');
  if(d.ok){ _mBindEmail=em; _mBindStep='verify'; $('m_codeField').style.display=''; $('mBindBtn').textContent='确认绑定'; }
}
async function mBindVerify(){
  const code=$('m_code').value.trim();
  if(!code){ showToast('请输入验证码','err'); return; }
  const d = await api('/api/account/email/verify','POST',{email:_mBindEmail,code:code});
  showToast(d.msg, d.ok?'ok':'err');
  if(d.ok) loadAccount();
}
async function mUnbindStart(){
  const d = await api('/api/account/email/unbind','POST',{send:true});
  showToast(d.msg, d.ok?'ok':'err');
  if(d.ok){ $('ubTarget').textContent='验证码已发送到当前绑定邮箱'; $('ub_code').value=''; $('ubMsg').textContent=''; $('ubMsg').className='msg'; $('unbindOverlay').classList.add('active'); }
}
function ubCancel(){ $('unbindOverlay').classList.remove('active'); }
async function ubSave(){
  const code=$('ub_code').value.trim();
  if(!code){ showToast('请输入验证码','err'); return; }
  const d = await api('/api/account/email/unbind','POST',{code:code});
  showToast(d.msg, d.ok?'ok':'err');
  if(d.ok){ ubCancel(); loadAccount(); }
}

// ---- SMTP 邮件服务 ----
async function loadMailConfig(){
  try{
    const d = await api('/api/mail/config');
    if(!d.ok){ showToast(d.msg,'err'); return; }
    const c = d.config||{};
    $('smtp_host').value=c.host||''; $('smtp_port').value=c.port||465;
    $('smtp_user').value=c.user||''; $('smtp_pwd').value='';
    $('smtp_from').value=c.from_addr||''; $('smtp_fromname').value=c.from_name||'';
    $('smtp_ssl').checked = c.use_ssl!==false;
    $('mailMsg').className='msg '+(c.configured?'ok':'err');
    $('mailMsg').textContent = c.configured ? ('已配置 '+c.host+'（'+(c.has_password?'密码已加密保存':'未设置密码')+'）') : '尚未配置 SMTP 服务';
  }catch(e){ showToast('加载配置失败','err'); }
}
async function saveMailConfig(){
  const body = {
    host:$('smtp_host').value.trim(), port:$('smtp_port').value.trim()||465,
    use_ssl:$('smtp_ssl').checked, user:$('smtp_user').value.trim(),
    password:$('smtp_pwd').value, from_addr:$('smtp_from').value.trim(), from_name:$('smtp_fromname').value.trim(),
  };
  if(!body.host){ showToast('SMTP 服务器地址不能为空','err'); return; }
  showConfirm('保存 SMTP 配置','确认保存该 SMTP 配置？密码将加密存储。', async function(){
    const d = await api('/api/mail/config','POST',body);
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok) loadMailConfig();
  });
}
async function testMail(){
  const to=$('smtp_testto').value.trim();
  if(!to){ showToast('请填写测试收件邮箱','err'); return; }
  $('mailTestMsg').textContent='正在发送…';
  const d = await api('/api/mail/test','POST',{to:to});
  showToast(d.msg||'发送失败', d.ok?'ok':'err');
}

// ---- SSRF 内网白名单 ----
async function loadSsrfConfig(){
  try{
    const d = await api('/api/ssrf/config');
    if(!d.ok){ showToast(d.msg,'err'); return; }
    SSRF_CACHE = d.allowlist||[];
    $('ssrfList').innerHTML = SSRF_CACHE.length ? SSRF_CACHE.map(c =>
      `<span style="display:inline-flex;align-items:center;gap:6px;padding:4px 10px;border-radius:14px;background:rgba(157,180,255,.15);border:1px solid rgba(157,180,255,.4);font-size:13px">${esc(c)} <a href="javascript:void(0)" onclick="delSsrf('${c}')" title="移除" style="color:#ff7b8a;font-weight:700">×</a></span>`
    ).join('') : '<span class="note">暂无白名单，插件访问本机/内网会被拦截</span>';
  }catch(e){ showToast('加载失败','err'); }
}
function addSsrf(){
  const v = $('ssrf_cidr').value.trim();
  if(!v){ showToast('请输入 CIDR 网段，如 127.0.0.1/32','err'); return; }
  showConfirm('添加白名单网段','确认放行 '+v+'？（未列入白名单的内网/环回/metadata 地址仍会被拦截）', async function(){
    const d = await api('/api/ssrf/config','POST',{allowlist: SSRF_CACHE.concat([v])});
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ SSRF_CACHE=d.allowlist||[]; $('ssrf_cidr').value=''; loadSsrfConfig(); }
  });
}
function delSsrf(c){
  showConfirm('移除白名单网段','确认移除 '+c+'？移除后该网段将恢复为拦截。', async function(){
    const d = await api('/api/ssrf/config','POST',{allowlist: SSRF_CACHE.filter(x=>x!==c)});
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ SSRF_CACHE=d.allowlist||[]; loadSsrfConfig(); }
  });
}

function applyRoleUI(){ $('tabBtnPlugins').style.display = IS_SUPER ? '' : 'none'; $('sys-mail').style.display = IS_SUPER ? '' : 'none'; $('sys-ssrf').style.display = IS_SUPER ? '' : 'none'; $('sysSuperBox').style.display = IS_SUPER ? '' : 'none'; }

async function loadPlugins(){
  try{
    const d = await api('/api/plugins');
    PLUG_CACHE = d.plugins||[];
    const rows = PLUG_CACHE.map(p => `
      <tr>
        <td><b>${esc(p.name||p.id)}</b>${p.builtin?' <span class="badge">内置</span>':''}<br><small>${esc(p.id)}</small></td>
        <td>${esc(p.version||'-')}</td>
        <td>${esc(p.author||'-')}</td>
        <td>${(p.permissions||[]).join('、')||'-'}</td>
        <td>${p.enabled?'<span class="ok">运行中</span>':'<span class="off">已停用</span>'}${p.ready?'':'<br><small class="off">异常</small>'}</td>
        <td>${p.trusted?'<span class="ok">已信任</span>':'<span class="warn">未信任</span>'}</td>
        <td class="op">
          ${p.enabled
            ? `<button class="btn ghost sm" onclick="plugOp('${p.id}','disable')">停用</button>`
            : `<button class="btn sm" onclick="plugEnable('${p.id}')">启用</button>`}
          <button class="btn ghost sm" onclick="plugOp('${p.id}','reload')">重载</button>
          ${p.builtin?'':`<button class="btn ghost sm danger" onclick="plugOp('${p.id}','remove')">卸载</button>`}
          <button class="btn ghost sm" onclick="plugTrust('${p.id}')">${p.trusted?'取消信任':'信任'}</button>
        </td>
      </tr>`).join('');
    $('pluginRows').innerHTML = rows || '<tr><td colspan="7" class="empty">暂无插件，点击「上传插件包」或「从 GitHub 安装」添加</td></tr>';
  }catch(e){ showToast('加载失败: '+e.message,'err'); }
}

async function plugEnable(id){
  const d = await api('/api/plugins/'+id+'/enable','POST');
  if(d.need_trust){
    const perms=(d.permissions||[]).join('、')||'无';
    showConfirm('信任并启用插件', '插件「'+d.name+'」申请权限：'+perms+'\n作者：'+d.author+'\n仓库：'+(d.repository||'未提供')+'\n\n信任后该插件可执行上述能力，请确认来源可信。', async function(){
      await api('/api/plugins/trust','POST',{id:id,trusted:true});
      const d2 = await api('/api/plugins/'+id+'/enable','POST');
      showToast(d2.msg||(d2.ok?'已启用':'启用失败'), d2.ok?'ok':'err');
      loadPlugins();
    });
    return;
  }
  showToast(d.msg||(d.ok?'已启用':'启用失败'), d.ok?'ok':'err');
  loadPlugins();
}

async function plugOp(id,op){
  const words={disable:'停用',reload:'热重载',remove:'卸载'};
  showConfirm(words[op]+'插件', '确认'+words[op]+'插件 '+id+'？'+(op==='remove'?'（将删除插件文件）':''), async function(){
    const d = await api('/api/plugins/'+id+'/'+op,'POST');
    showToast(d.msg||(d.ok?'操作成功':'操作失败'), d.ok?'ok':'err');
    loadPlugins();
  });
}

async function plugTrust(id){
  const p = PLUG_CACHE.find(x=>x.id===id);
  showConfirm(p.trusted?'取消信任':'信任插件', (p.trusted?'取消信任后启用需再次确认':'信任后可在权限确认后直接启用')+'，插件：'+id, async function(){
    const d = await api('/api/plugins/trust','POST',{id:id,trusted:!p.trusted});
    showToast(d.msg, d.ok?'ok':'err');
    loadPlugins();
  });
}

function uploadPlugin(){ $('pluginFile').click(); }
async function doUploadPlugin(){
  const f = $('pluginFile').files[0];
  if(!f) return;
  const fd = new FormData(); fd.append('file', f);
  const res = await fetch('/api/plugins/upload', {method:'POST', headers:{'Authorization':'Bearer '+TOKEN}, body:fd});
  const d = await res.json();
  showToast(d.msg||'上传失败', d.ok?'ok':'err');
  loadPlugins();
}

async function installGithub(){
  const url = prompt('请输入 GitHub 仓库地址（如 https://github.com/owner/repo）');
  if(!url) return;
  showConfirm('从 GitHub 安装', '将从 '+url+' 拉取代码安装插件，确认？', async function(){
    const d = await api('/api/plugins/github','POST',{url:url.trim()});
    showToast(d.msg||'安装失败', d.ok?'ok':'err');
    loadPlugins();
  });
}

function esc(s){ return String(s==null?'':s).replace(/[&<>"']/g, c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;',"'":'&#39;'}[c])); }

document.getElementById('pluginFile').addEventListener('change', doUploadPlugin);

async function loadAdmins(){
  try{
    const d = await api('/api/admins');
    $('adminRows').innerHTML = (d.admins||[]).map(a => `
      <tr>
        <td>${a.username}${a.self?' <span class="note">(当前)</span>':''}</td>
        <td><span class="dot ${a.is_super?'on':'off'}"></span>${a.is_super?'超级管理员':'管理员'}</td>
        <td class="mono">${a.email||'-'}</td>
        <td class="mono">${a.created_at||'-'}</td>
        <td>
          ${(a.is_super||a.self)?'':`<button class="btn ghost sm" onclick="resetAdminPwd('${a.username}')">重置密码</button>`}
          ${(a.is_super||a.self)?'':`<button class="btn ${a.enabled?'ghost':'ok'} sm" onclick="toggleAdmin('${a.username}',${a.enabled?'true':'false'})">${a.enabled?'停用':'启用'}</button>`}
          ${(a.is_super||a.self)?'':`<button class="btn danger sm" onclick="delAdmin('${a.username}')">删除</button>`}
        </td>
      </tr>`).join('') || '<tr><td colspan="5" class="empty">暂无管理员</td></tr>';
  }catch(e){}
}

async function addAdmin(){
  const u=$('a_name').value.trim(), p=$('a_pwd').value, e=$('a_email').value.trim();
  if(!u || !p){ showToast('请填写用户名和密码','err'); return; }
  if(!e){ showToast('请填写邮箱','err'); return; }
  showConfirm('新增管理员','确认添加管理员「'+u+'」？', async function(){
    const d = await api('/api/admins','POST',{ username:u, password:p, email:e });
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ $('a_name').value=''; $('a_pwd').value=''; $('a_email').value=''; loadAdmins(); }
  });
}

let _rpUser=null;
function resetAdminPwd(u){ _rpUser=u; $('rpTarget').textContent='目标账号：'+u; $('rp_new').value=''; $('resetPwdOverlay').classList.add('active'); }
function rpCancel(){ $('resetPwdOverlay').classList.remove('active'); _rpUser=null; }
async function rpSave(){
  const u=_rpUser, p=$('rp_new').value;
  if(!u) return;
  if(p.length<8){ showToast('密码至少 8 位','err'); return; }
  showConfirm('重置密码','确认重置「'+u+'」的密码？其所有登录会话将下线。', async function(){
    const d = await api('/api/admins/'+encodeURIComponent(u)+'/reset-pwd','POST',{ password:p });
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok){ rpCancel(); loadAdmins(); }
  });
}

async function delAdmin(u){
  showConfirm('删除管理员','确认删除管理员「'+u+'」？删除后其将无法再登录。', async function(){
    const d = await api('/api/admins/'+encodeURIComponent(u),'DELETE');
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok) loadAdmins();
  });
}

async function toggleAdmin(u, cur){
  const act = cur ? '停用' : '启用';
  showConfirm(act+'管理员', '确认'+act+'管理员「'+u+'」？'+(cur?'停用后其将无法登录，当前会话会立即下线。':''), async function(){
    const d = await api('/api/admins/'+encodeURIComponent(u)+'/toggle','POST');
    showToast(d.msg, d.ok?'ok':'err');
    if(d.ok) loadAdmins();
  });
}

document.querySelectorAll('.tab').forEach(btn => {
  btn.onclick = () => {
    document.querySelectorAll('.tab').forEach(b=>b.classList.remove('active'));
    document.querySelectorAll('.tabPage').forEach(p=>p.classList.remove('active'));
    btn.classList.add('active');
    $('tab-'+btn.dataset.tab).classList.add('active');
    if(btn.dataset.tab==='bots') loadBots();
    if(btn.dataset.tab==='logs') loadCalls();
    if(btn.dataset.tab==='sessions') loadSessions();
    if(btn.dataset.tab==='plugins') loadPlugins();
    if(btn.dataset.tab==='system'){ if(IS_SUPER){ loadAdmins(); loadMailConfig(); loadSsrfConfig(); } loadAccount(); }
  };
});

function init(){ loadBots(); }

/* ---- 首次安装向导（WP 风格：面板内建号）---- */
let SETUP_TOKEN = '';
function showSetup(token){
  SETUP_TOKEN = token || '';
  $('setupView').classList.add('active');
  $('loginView').classList.remove('active');
  $('mainView').classList.remove('active');
}
async function doSetup(){
  const u = $('setupUser').value.trim(), p = $('setupPass').value, p2 = $('setupPass2').value, e = $('setupEmail').value.trim();
  if(!u){ showToast('请输入管理员用户名','err'); return; }
  if(p.length < 8){ showToast('密码至少 8 位','err'); return; }
  if(p !== p2){ showToast('两次输入的密码不一致','err'); return; }
  if(!e || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(e)){ showToast('请输入正确的邮箱','err'); return; }
  $('setupBtn').disabled = true;
  try{
    const res = await fetch('/api/setup', { method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({token:SETUP_TOKEN, username:u, password:p, email:e}) });
    const d = await res.json();
    if(d.ok){
      showToast('初始化完成，请登录','ok');
      $('setupView').classList.remove('active');
      $('username').value = u;
      $('password').value = '';
      showLogin();
      $('password').focus();
    } else {
      showToast(d.msg || '初始化失败','err');
    }
  }catch(err){
    showToast('网络错误，请重试','err');
  }finally{
    $('setupBtn').disabled = false;
  }
}

(async function(){
  try{
    const st = await fetch('/api/setup/status').then(r=>r.json());
    if(st && st.needs_setup){ showSetup(st.token || ''); return; }
  }catch(e){}
  if(TOKEN){
    try{ const d = await api('/api/session'); IS_SUPER = !!d.is_super; localStorage.setItem('gw_is_super', IS_SUPER?'1':''); $('userTag').textContent = d.username; applyRoleUI(); showMain(); init(); return; }catch(e){}
  }
  showLogin();
})();
</script>
<div class="footer-copy">©2026 米尔文学工作室 All Rights Reserved</div>

<script>
(function () {
  var canvas = document.getElementById('gradient-waves');
  if (!canvas) return;
  var gl = canvas.getContext('webgl2', { alpha: true, premultipliedAlpha: true, antialias: false });
  if (!gl) { canvas.style.display = 'none'; return; }

  function hexToRgb(hex) {
    var m = /^#?([a-f\d]{2})([a-f\d]{2})([a-f\d]{2})$/i.exec(hex);
    if (!m) return [1, 1, 1];
    return [parseInt(m[1], 16) / 255, parseInt(m[2], 16) / 255, parseInt(m[3], 16) / 255];
  }

  var vsSrc = `#version 300 es
in vec2 position;
void main() {
  gl_Position = vec4(position, 0.0, 1.0);
}
`;

  var fsSrc = `#version 300 es
precision highp float;
uniform vec2 iResolution;
uniform float iTime;
uniform float uSpeed;
uniform float uAmplitude;
uniform float uWaveScale;
uniform float uWaveRatio;
uniform float uSwell;
uniform float uTurbulence;
uniform float uTilt;
uniform float uZoom;
uniform float uHeight;
uniform float uFogDepth;
uniform float uSteps;
uniform float uBrightness;
uniform float uOpacity;
uniform float uGrain;
uniform float uGrainIntensity;
uniform vec2 uMouse;
uniform float uParallax;
uniform bool uEnableMouse;
uniform vec3 uHorizonColor;
uniform vec3 uWaveColor;
uniform vec3 uCrestColor;
out vec4 fragColor;

const float MAX_DIST = 20000.0;

float hash21(vec2 p) {
  vec3 p3 = fract(vec3(p.xyx) * 0.1031);
  p3 += dot(p3, p3.yzx + 33.33);
  return fract((p3.x + p3.y) * p3.z);
}

float plasma(vec3 r, vec2 freq, vec4 tc) {
  float mx = r.x + tc.x;
  mx += uSwell * sin((r.y + mx) / 20.0 + tc.y);
  float my = r.y - tc.z;
  my += uTurbulence * cos(r.x / 23.0 + tc.w);
  return r.z - (sin(mx * freq.x) * uAmplitude + sin(my * freq.y) * uAmplitude + uHeight);
}

float raymarch(vec3 pos, vec3 dir, vec2 freq, vec4 tc) {
  float dist = 0.0;
  for (int i = 0; i < 128; i++) {
    if (float(i) >= uSteps) break;
    float dscene = plasma(pos + dist * dir, freq, tc);
    if (abs(dscene) < 0.1) break;
    dist += 0.9 * dscene;
    if (!(abs(dist) < MAX_DIST)) return MAX_DIST;
  }
  return dist;
}

void main() {
  float T = iTime * uSpeed;
  vec2 freq = vec2(uWaveScale / 7.0, (uWaveScale * uWaveRatio) / 3.0);
  vec4 tc = vec4(T / 0.130, T / 0.810, T / 0.200, T / 0.710);
  float c, s;
  float vfov = (3.14159 / 2.3) / max(uZoom, 0.05);
  vec3 cam = vec3(0.0, 0.0, 30.0);
  vec2 uv = (gl_FragCoord.xy / iResolution.xy) - 0.5;
  uv.x *= iResolution.x / iResolution.y;
  uv.y *= -1.0;

  vec3 dir = vec3(0.0, 0.0, -1.0);
  float ulen = length(uv);
  float xrot = vfov * ulen;
  c = cos(xrot); s = sin(xrot);
  dir = mat3(1.0, 0.0, 0.0, 0.0, c, -s, 0.0, s, c) * dir;
  vec2 nuv = ulen > 1e-5 ? uv / ulen : vec2(1.0, 0.0);
  c = nuv.x; s = nuv.y;
  dir = mat3(c, -s, 0.0, s, c, 0.0, 0.0, 0.0, 1.0) * dir;
  c = cos(uTilt); s = sin(uTilt);
  dir = mat3(c, 0.0, s, 0.0, 1.0, 0.0, -s, 0.0, c) * dir;

  if (uEnableMouse) {
    float yaw = (uMouse.x - 0.5) * uParallax * 0.4;
    float pitch = (uMouse.y - 0.5) * uParallax * 0.4;
    c = cos(yaw); s = sin(yaw);
    dir = mat3(c, 0.0, s, 0.0, 1.0, 0.0, -s, 0.0, c) * dir;
    c = cos(pitch); s = sin(pitch);
    dir = mat3(1.0, 0.0, 0.0, 0.0, c, -s, 0.0, s, c) * dir;
  }

  float dist = raymarch(cam, dir, freq, tc);
  vec3 pos = cam + dist * dir;

  float t = clamp(uFogDepth / max(dist, 0.001), 0.0, 1.0);
  vec3 body = mix(uWaveColor, uCrestColor, clamp(pos.z * 0.08 + 0.5, 0.0, 1.0));
  vec3 col = mix(uHorizonColor, body, t);
  col *= uBrightness;
  col = clamp(col, 0.0, 1.0);

  float alpha = clamp(t, 0.0, 1.0) * uOpacity;
  if (uGrain > 0.5) {
    float g = hash21(gl_FragCoord.xy + mod(iTime, 64.0) * 11.0);
    alpha += (g - 0.5) * uGrainIntensity;
  }
  alpha = clamp(alpha, 0.0, 1.0);
  fragColor = vec4(col * alpha, alpha);
}
`;

  function compile(type, src) {
    var sh = gl.createShader(type);
    gl.shaderSource(sh, src);
    gl.compileShader(sh);
    if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) {
      console.error(gl.getShaderInfoLog(sh));
      return null;
    }
    return sh;
  }
  var vs = compile(gl.VERTEX_SHADER, vsSrc);
  var fs = compile(gl.FRAGMENT_SHADER, fsSrc);
  if (!vs || !fs) return;
  var prog = gl.createProgram();
  gl.attachShader(prog, vs);
  gl.attachShader(prog, fs);
  gl.linkProgram(prog);
  gl.useProgram(prog);

  // 全屏三角形
  var buf = gl.createBuffer();
  gl.bindBuffer(gl.ARRAY_BUFFER, buf);
  gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1, -1, 3, -1, -1, 3]), gl.STATIC_DRAW);
  var loc = gl.getAttribLocation(prog, 'position');
  gl.enableVertexAttribArray(loc);
  gl.vertexAttribPointer(loc, 2, gl.FLOAT, false, 0, 0);

  function u(name) { return gl.getUniformLocation(prog, name); }
  var uni = {
    iResolution: u('iResolution'), iTime: u('iTime'),
    uSpeed: u('uSpeed'), uAmplitude: u('uAmplitude'), uWaveScale: u('uWaveScale'),
    uWaveRatio: u('uWaveRatio'), uSwell: u('uSwell'), uTurbulence: u('uTurbulence'),
    uTilt: u('uTilt'), uZoom: u('uZoom'), uHeight: u('uHeight'), uFogDepth: u('uFogDepth'),
    uSteps: u('uSteps'), uBrightness: u('uBrightness'), uOpacity: u('uOpacity'),
    uGrain: u('uGrain'), uGrainIntensity: u('uGrainIntensity'),
    uMouse: u('uMouse'), uParallax: u('uParallax'), uEnableMouse: u('uEnableMouse'),
    uHorizonColor: u('uHorizonColor'), uWaveColor: u('uWaveColor'), uCrestColor: u('uCrestColor')
  };

  gl.clearColor(0, 0, 0, 0);
  var res = new Float32Array([1, 1]);
  gl.uniform2fv(uni.iResolution, res);
  gl.uniform1f(uni.uSpeed, 0.4);
  gl.uniform1f(uni.uAmplitude, 2.5);
  gl.uniform1f(uni.uWaveScale, 0.6);
  gl.uniform1f(uni.uWaveRatio, 0.9);
  gl.uniform1f(uni.uSwell, 35);
  gl.uniform1f(uni.uTurbulence, 20);
  gl.uniform1f(uni.uTilt, 1.11);
  gl.uniform1f(uni.uZoom, 1.0);
  gl.uniform1f(uni.uHeight, 5.5);
  gl.uniform1f(uni.uFogDepth, 15);
  gl.uniform1f(uni.uSteps, 70.0);
  gl.uniform1f(uni.uBrightness, 1.0);
  gl.uniform1f(uni.uOpacity, 1.0);
  gl.uniform1f(uni.uGrain, 1.0);
  gl.uniform1f(uni.uGrainIntensity, 0.05);
  var m = new Float32Array([0.5, 0.5]);
  gl.uniform2fv(uni.uMouse, m);
  gl.uniform1f(uni.uParallax, 0.5);
  gl.uniform1i(uni.uEnableMouse, 1);
  var hc = hexToRgb('#a08de9'), wc = hexToRgb('#FF9FFC'), cc = hexToRgb('#FFFFFF');
  gl.uniform3fv(uni.uHorizonColor, new Float32Array(hc));
  gl.uniform3fv(uni.uWaveColor, new Float32Array(wc));
  gl.uniform3fv(uni.uCrestColor, new Float32Array(cc));

  function setSize() {
    var dpr = Math.min(window.devicePixelRatio || 1, 2);
    var w = Math.max(1, canvas.clientWidth), h = Math.max(1, canvas.clientHeight);
    canvas.width = Math.floor(w * dpr);
    canvas.height = Math.floor(h * dpr);
    gl.viewport(0, 0, canvas.width, canvas.height);
    res[0] = canvas.width; res[1] = canvas.height;
    gl.uniform2fv(uni.iResolution, res);
  }
  var ro = new ResizeObserver(setSize);
  ro.observe(canvas);
  setSize();

  var cur = [0.5, 0.5], target = [0.5, 0.5];
  canvas.addEventListener('pointermove', function (e) {
    var r = canvas.getBoundingClientRect();
    target[0] = (e.clientX - r.left) / r.width;
    target[1] = 1.0 - (e.clientY - r.top) / r.height;
  });
  canvas.addEventListener('pointerleave', function () { target[0] = 0.5; target[1] = 0.5; });

  var raf = 0, isVisible = true, isPageVisible = !document.hidden, t0 = performance.now();
  function loop(t) {
    gl.uniform1f(uni.iTime, (t - t0) * 0.001);
    cur[0] += 0.05 * (target[0] - cur[0]);
    cur[1] += 0.05 * (target[1] - cur[1]);
    gl.uniform2fv(uni.uMouse, new Float32Array(cur));
    gl.clear(gl.COLOR_BUFFER_BIT);
    gl.drawArrays(gl.TRIANGLES, 0, 3);
    raf = requestAnimationFrame(loop);
  }
  function tryStart() { if (isVisible && isPageVisible && raf === 0) raf = requestAnimationFrame(loop); }
  function tryStop() { if (raf !== 0) { cancelAnimationFrame(raf); raf = 0; } }
  var io = new IntersectionObserver(function (es) {
    isVisible = es[0].isIntersecting;
    isVisible ? tryStart() : tryStop();
  }, { threshold: 0 });
  io.observe(canvas);
  document.addEventListener('visibilitychange', function () {
    isPageVisible = !document.hidden;
    isPageVisible ? tryStart() : tryStop();
  });
  tryStart();
})();
</script>

<div id="toastWrap"></div>
</body>
</html>"""


# ================= 主入口 =================
def main():
    print('=' * 60, flush=True)
    print('[QQBOT] SUPERNOVA 网关（多机器人 + 管理面板）', flush=True)
    print(f'[QQBOT] 面板地址: http://{PANEL_HOST}:{PANEL_PORT}', flush=True)
    print(f'[QQBOT] 配置目录: {SCRIPT_DIR}', flush=True)
    print('=' * 60, flush=True)

    global PLUGIN_MGR
    ensure_admin()
    if PluginManager is not None:
        PLUGIN_MGR = PluginManager(
            PLUGINS_DIR,
            audit_fn=lambda action, who, by, detail='': _audit(action, who, by, detail),
            host_handlers={
                'http_request': _plugin_http_request,
                'get_bot_list': _plugin_get_bots,
                'log': _plugin_log,
                'emit_event': _plugin_emit,
                '_send_message': _plugin_send_from_host,
            },
            logger=lambda msg: print(msg, flush=True),
        )
        PLUGIN_MGR.start()
        print(f'[PLUGIN] 插件管理器已启动，目录: {PLUGINS_DIR}', flush=True)
    else:
        print('[PLUGIN] 警告：未找到 plugin_manager.py，插件系统不可用。', flush=True)
    bots = load_bots()
    if not bots:
        print('[QQBOT] 警告：bots_config.json 无有效机器人，可在管理面板中添加。', flush=True)
    started = start_all_bots(bots) if bots else 0
    print(f'[QQBOT] 已启动 {started} 个机器人线程。', flush=True)

    def _shutdown(signum, frame):
        print('[QQBOT] 收到退出信号，正在清理...', flush=True)
        if PLUGIN_MGR is not None:
            try:
                PLUGIN_MGR.stop()
            except Exception as e:
                print(f'[QQBOT] 清理插件进程异常: {e}', flush=True)
        os._exit(0)

    try:
        signal.signal(signal.SIGTERM, _shutdown)
    except (ValueError, OSError):
        pass
    try:
        signal.signal(signal.SIGINT, _shutdown)
    except (ValueError, OSError):
        pass

    # Flask 生产模式运行（debug 必须关闭）；生产环境建议置于 Nginx/Caddy HTTPS 之后
    app.run(host=PANEL_HOST, port=PANEL_PORT, debug=False, threaded=True)


if __name__ == '__main__':
    main()