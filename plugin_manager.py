# -*- coding: utf-8 -*-
"""插件管理器 —— 网关主进程内的独立模块（一期内嵌，二期整体拆为独立宿主进程）。

== 职责 ==
- 扫描 plugins/ 目录，解析 manifest，维护插件清单
- 每个插件拉起一个独立 worker 子进程（plugin_worker.py），通过 stdio JSON 行协议通信
- 热加载：监听插件目录变化，新增/修改/删除不重启网关
- 消息分发：按 机器人->插件 绑定规则，把事件交给插件处理
- host API 代理：处理 worker 反向请求（send_text / http_request / get_bot_list 等）
- 崩溃自愈：worker 异常退出自动重启（指数退避），连续失败自动停用
- 信任机制：安装/启用时登记信任状态与权限清单，白名单插件免确认
- 定时器：按 manifest 声明的 timers 周期触发 on_timer
- 审计：安装/更新/启用/停用/崩溃/越权等全部记录

== 二期拆分 ==
接口（消息协议、manifest、插件 API）一次定死；二期把本模块搬入 plugin_host.py 独立进程，
与网关之间的本地通道由 subprocess stdio 平移到 socket/HTTP，插件规范零改动。
"""
import os
import sys
import json
import time
import shutil
import zipfile
import threading
import subprocess
import tempfile
import hashlib

WORKER_TIMEOUT = 15          # 单次插件调用超时（秒）
SCAN_INTERVAL = 3            # 热加载扫描间隔（秒）
MAX_CRASH = 5                # 连续崩溃上限
BACKOFF_BASE = 2             # 崩溃重启退避基数（秒）


class PluginRecord:
    """单个插件的运行态记录。"""

    def __init__(self, manifest, plugin_dir):
        self.manifest = manifest
        self.plugin_dir = plugin_dir
        self.plugin_id = manifest.get('id') or os.path.basename(plugin_dir)
        self.proc = None          # subprocess.Popen
        self.stdout_reader = None
        self.stdin_lock = threading.Lock()
        self.ready = False        # worker load 完成
        self.enabled = True
        self.builtin = bool(manifest.get('builtin'))
        self.crash_count = 0
        self.next_restart = 0.0
        self.manifest_hash = self._hash()
        self.code_hash = self._hash_code()
        self.last_error = ''
        self.started_at = None
        self.stop_event = threading.Event()
        self._seq = 0
        self._pending = {}
        self._pending_lock = threading.Lock()
        self._outbox_queue = []   # worker 带回来的待发送消息
        self._outbox_lock = threading.Lock()

    def _hash(self):
        try:
            with open(os.path.join(self.plugin_dir, 'manifest.json'), 'rb') as f:
                return hash(f.read())
        except Exception:
            return 0

    def _hash_code(self):
        """聚合插件目录内所有 .py 与 manifest.json 的内容哈希（md5，跨进程稳定）。"""
        h = hashlib.md5()
        files = []
        for root, _, names in os.walk(self.plugin_dir):
            for fn in names:
                if fn.endswith('.py') or fn == 'manifest.json':
                    files.append(os.path.join(root, fn))
        for fp in sorted(files):
            try:
                with open(fp, 'rb') as f:
                    h.update(fp.encode('utf-8'))
                    h.update(f.read())
            except Exception:
                pass
        return h.hexdigest()


class PluginManager:
    def __init__(self, plugin_dir, audit_fn=None, host_handlers=None, logger=None):
        self.plugin_dir = os.path.abspath(plugin_dir)
        self.audit = audit_fn or (lambda *a, **k: None)
        self.logger = logger or (lambda *a: None)
        self.host_handlers = host_handlers or {}
        self.workers = {}          # plugin_id -> PluginRecord
        self.lock = threading.Lock()
        self._scan_timer = None
        self._stop = threading.Event()
        self._next_seq = 0
        os.makedirs(self.plugin_dir, exist_ok=True)

    # ================= 进程与通信 =================
    def _next_req(self, rec):
        with rec._pending_lock:
            rec._seq += 1
            return rec._seq

    def _spawn_worker(self, rec):
        """拉起 worker 子进程并启动 stdout 读取线程。"""
        if rec.proc and rec.proc.poll() is None:
            return
        rec.stop_event.clear()
        try:
            python = sys.executable
            worker_py = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'plugin_worker.py')
            rec.proc = subprocess.Popen(
                [python, worker_py, rec.plugin_dir],
                stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True, encoding='utf-8', errors='replace',
                cwd=rec.plugin_dir, bufsize=1,
                creationflags=getattr(subprocess, 'CREATE_NO_WINDOW', 0),
            )
            rec.started_at = time.time()
            rec.stdout_reader = threading.Thread(
                target=self._reader_loop, args=(rec,), daemon=True)
            rec.stdout_reader.start()
            rec.ready = False
            # 发送 load 指令
            self._send(rec, {'op': 'load', 'manifest': rec.manifest})
        except Exception as e:
            rec.last_error = f'spawn failed: {e}'
            self.logger(f'[PLUGIN] spawn {rec.plugin_id} failed: {e}')

    def _send(self, rec, msg):
        if not rec.proc or rec.proc.poll() is not None:
            return False
        try:
            with rec.stdin_lock:
                rec.proc.stdin.write(json.dumps(msg, ensure_ascii=False) + '\n')
                rec.proc.stdin.flush()
            return True
        except Exception:
            return False

    def _reader_loop(self, rec):
        while not rec.stop_event.is_set() and rec.proc and rec.proc.poll() is None:
            line = rec.proc.stdout.readline()
            if not line:
                break
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except Exception:
                self.logger(f'[PLUGIN] {rec.plugin_id} 非协议输出: {line[:200]}')
                continue
            op = msg.get('op')
            if op == 'ready':
                rec.ready = bool(msg.get('ok'))
                if not rec.ready:
                    rec.last_error = msg.get('error') or 'load failed'
                    self.logger(f'[PLUGIN] {rec.plugin_id} 加载失败: {rec.last_error}')
                    rec.crash_count += 1
                else:
                    rec.last_error = ''
                    self.audit('plugin_loaded', rec.plugin_id, 'worker',
                               f'插件已加载 v{rec.manifest.get("version") or "?"}')
                    self._schedule_timers(rec)
            elif op == 'result':
                self._resolve(rec, msg.get('req_id'), msg)
            elif op == 'host_call':
                self._handle_host_call(rec, msg)
            elif op == 'exited':
                break
            else:
                self.logger(f'[PLUGIN] {rec.plugin_id} 未知消息: {op}')

    def _resolve(self, rec, req_id, msg):
        with rec._pending_lock:
            item = rec._pending.pop(req_id, None)
        if not item:
            return
        ev, box = item
        box['msg'] = msg
        ev.set()

    def call(self, plugin_id, hook, ctx, timeout=WORKER_TIMEOUT):
        """同步调用插件钩子；返回 (ok, value, outbox, error)。"""
        with self.lock:
            rec = self.workers.get(plugin_id)
        if not rec or not rec.ready or not rec.enabled:
            return False, None, [], '插件不可用'
        req_id = self._next_req(rec)
        ev = threading.Event()
        box = {}
        with rec._pending_lock:
            rec._pending[req_id] = (ev, box)
        if not self._send(rec, {'op': 'call', 'hook': hook, 'ctx': ctx, 'req_id': req_id}):
            with rec._pending_lock:
                rec._pending.pop(req_id, None)
            return False, None, [], '发送失败'
        if not ev.wait(timeout):
            with rec._pending_lock:
                rec._pending.pop(req_id, None)
            self._kill(rec, reason='timeout')
            return False, None, [], '调用超时（已重启 worker）'
        msg = box.get('msg') or {}
        ok = msg.get('ok', False)
        value = msg.get('value')
        outbox = msg.get('outbox') or []
        error = msg.get('error') or ''
        if not ok and error:
            rec.last_error = error
            self.logger(f'[PLUGIN] {plugin_id}.{hook} 异常: {error[:300]}')
        return ok, value, outbox, error

    def _kill(self, rec, reason=''):
        rec.ready = False
        try:
            self._send(rec, {'op': 'shutdown'})
        except Exception:
            pass
        if rec.proc:
            try:
                rec.proc.kill()
            except Exception:
                pass
            rec.proc = None
        if reason:
            self.audit('plugin_killed', rec.plugin_id, 'manager', reason)

    def _handle_host_call(self, rec, msg):
        """处理 worker 反向能力请求。"""
        method = msg.get('method')
        args = msg.get('args') or {}
        handler = self.host_handlers.get(method)
        if not handler:
            self._send(rec, {'op': 'host_result', 'req_id': msg.get('req_id'),
                             'ok': False, 'error': f'未知 host 能力: {method}'})
            return
        try:
            value = handler(rec, args)
            self._send(rec, {'op': 'host_result', 'req_id': msg.get('req_id'),
                             'ok': True, 'value': value})
        except Exception as e:
            self._send(rec, {'op': 'host_result', 'req_id': msg.get('req_id'),
                             'ok': False, 'error': f'{type(e).__name__}: {e}'})

    # ================= 插件清单与热加载 =================
    def scan(self):
        """扫描插件目录，增量加载/重载/卸载。返回变更摘要。"""
        changed = []
        try:
            entries = {d for d in os.listdir(self.plugin_dir)
                       if os.path.isdir(os.path.join(self.plugin_dir, d))}
        except Exception:
            entries = set()
        # 校验每个目录
        for name in entries:
            pdir = os.path.join(self.plugin_dir, name)
            mpath = os.path.join(pdir, 'manifest.json')
            if not os.path.exists(mpath):
                continue
            try:
                with open(mpath, 'r', encoding='utf-8') as f:
                    manifest = json.load(f)
            except Exception as e:
                self.logger(f'[PLUGIN] {name} manifest 解析失败: {e}')
                continue
            pid = manifest.get('id') or name
            if pid in self.workers:
                rec = self.workers[pid]
                if rec.manifest_hash != self._hash_manifest(mpath) or \
                        rec.code_hash != rec._hash_code():
                    self.reload(pid)
                    changed.append(f'{pid}:reload')
            else:
                self._add_plugin(pid, manifest, pdir)
                changed.append(f'{pid}:add')
        # 清理已删除的插件目录
        for pid in list(self.workers.keys()):
            rec = self.workers[pid]
            if not os.path.isdir(rec.plugin_dir):
                self.remove(pid, keep_dir=False)
                changed.append(f'{pid}:remove')
        return changed

    def _hash_manifest(self, path):
        try:
            with open(path, 'rb') as f:
                return hash(f.read())
        except Exception:
            return 0

    def _add_plugin(self, pid, manifest, pdir):
        with self.lock:
            rec = PluginRecord(manifest, pdir)
            self.workers[pid] = rec
        self.logger(f'[PLUGIN] 发现插件: {manifest.get("name")} ({pid})')
        if rec.enabled:
            self._spawn_worker(rec)

    def reload(self, pid):
        with self.lock:
            rec = self.workers.get(pid)
            if not rec:
                return False
            rec.stop_event.set()
            self._kill(rec, reason='reload')
            try:
                with open(os.path.join(rec.plugin_dir, 'manifest.json'), 'r', encoding='utf-8') as f:
                    rec.manifest = json.load(f)
                rec.manifest_hash = rec._hash()
                rec.code_hash = rec._hash_code()
            except Exception:
                pass
            rec.stop_event = threading.Event()
            rec.enabled = True
            rec.crash_count = 0
            rec.next_restart = 0.0
            self._spawn_worker(rec)
        self.audit('plugin_reloaded', pid, 'manager', '热重载')
        return True

    def remove(self, pid, keep_dir=True):
        with self.lock:
            rec = self.workers.pop(pid, None)
        if rec:
            rec.stop_event.set()
            self._kill(rec, reason='remove')
            if not keep_dir:
                try:
                    shutil.rmtree(rec.plugin_dir, ignore_errors=True)
                except Exception:
                    pass
        return True

    def set_enabled(self, pid, enabled):
        with self.lock:
            rec = self.workers.get(pid)
            if not rec:
                return False, '插件不存在'
            rec.enabled = enabled
            if enabled:
                rec.crash_count = 0
                rec.next_restart = 0.0
                self._spawn_worker(rec)
            else:
                rec.stop_event.set()
                self._kill(rec, reason='disable')
        self.audit('plugin_enable' if enabled else 'plugin_disable', pid, 'manager', '面板操作')
        return True, 'ok'

    # ================= 崩溃自愈 =================
    def _monitor_loop(self):
        while not self._stop.is_set():
            time.sleep(1)
            with self.lock:
                items = list(self.workers.items())
            for pid, rec in items:
                if not rec.enabled:
                    continue
                dead = (rec.proc is None) or (rec.proc.poll() is not None)
                if dead and rec.ready:
                    # 曾正常加载但进程死了
                    rec.crash_count += 1
                    rec.ready = False
                    self.audit('plugin_crash', pid, 'worker', f'进程异常退出（第{rec.crash_count}次）')
                if dead and rec.enabled and not rec.ready:
                    now = time.time()
                    if now < rec.next_restart:
                        continue
                    if rec.crash_count >= MAX_CRASH:
                        rec.enabled = False
                        self.audit('plugin_disabled', pid, 'manager', '连续崩溃，已自动停用')
                        continue
                    rec.next_restart = now + BACKOFF_BASE ** min(rec.crash_count, 5)
                    self.logger(f'[PLUGIN] {pid} 正在重启（第{rec.crash_count}次，{BACKOFF_BASE ** min(rec.crash_count, 5)}s 后）')
                    self._spawn_worker(rec)

    # ================= 定时器 =================
    def _schedule_timers(self, rec):
        timers = rec.manifest.get('timers') or []
        for t in timers:
            interval = int(t.get('interval') or 0)
            if interval <= 0:
                continue
            name = t.get('name') or t.get('id') or 'timer'
            threading.Thread(target=self._timer_loop, args=(rec.plugin_id, name, interval),
                             daemon=True).start()

    def _timer_loop(self, pid, name, interval):
        while not self._stop.is_set():
            time.sleep(interval)
            with self.lock:
                rec = self.workers.get(pid)
            if not rec or not rec.ready or not rec.enabled:
                return
            ok, value, outbox, err = self.call(pid, 'on_timer',
                                               {'name': name, 'at': time.strftime('%Y-%m-%d %H:%M:%S')},
                                               timeout=WORKER_TIMEOUT)
            self._deliver_outbox(outbox)
            if not ok and err:
                self.audit('plugin_timer_error', pid, 'timer', err[:200])

    # ================= 发送队列 =================
    def _deliver_outbox(self, outbox):
        """把 worker 返回的待发送消息交给网关统一发送（由网关侧注册 sender）。"""
        sender = self.host_handlers.get('_send_message')
        if not sender:
            return
        for item in outbox or []:
            try:
                sender(item.get('bot'), item.get('target'), item.get('text'))
            except Exception as e:
                self.logger(f'[PLUGIN] 发送失败: {e}')

    # ================= 生命周期 =================
    def start(self):
        self.scan()
        threading.Thread(target=self._scan_loop, daemon=True).start()
        threading.Thread(target=self._monitor_loop, daemon=True).start()

    def _scan_loop(self):
        while not self._stop.is_set():
            time.sleep(SCAN_INTERVAL)
            try:
                self.scan()
            except Exception as e:
                self.logger(f'[PLUGIN] 扫描异常: {e}')

    def stop(self):
        self._stop.set()
        with self.lock:
            for pid, rec in self.workers.items():
                rec.stop_event.set()
                self._kill(rec, reason='shutdown')

    # ================= 面板数据 =================
    def snapshot(self):
        out = []
        with self.lock:
            for pid, rec in self.workers.items():
                proc_state = 'running' if (rec.proc and rec.proc.poll() is None) else 'stopped'
                out.append({
                    'id': pid,
                    'name': rec.manifest.get('name') or pid,
                    'version': rec.manifest.get('version') or '-',
                    'author': rec.manifest.get('author') or '-',
                    'description': rec.manifest.get('description') or '',
                    'repository': rec.manifest.get('repository') or '',
                    'permissions': rec.manifest.get('permissions') or [],
                    'hooks': rec.manifest.get('hooks') or [],
                    'bot_binding': rec.manifest.get('bot_binding') or '',
                    'builtin': rec.builtin,
                    'enabled': rec.enabled,
                    'ready': rec.ready,
                    'proc_state': proc_state,
                    'crash_count': rec.crash_count,
                    'last_error': rec.last_error[:300],
                    'started_at': rec.started_at,
                    'plugin_dir': rec.plugin_dir,
                })
        out.sort(key=lambda x: (not x['builtin'], x['id']))
        return out

    def get(self, pid):
        with self.lock:
            rec = self.workers.get(pid)
            if not rec:
                return None
            return {
                'id': rec.plugin_id,
                'manifest': rec.manifest,
                'enabled': rec.enabled,
                'ready': rec.ready,
                'proc_state': 'running' if (rec.proc and rec.proc.poll() is None) else 'stopped',
                'last_error': rec.last_error[:500],
                'plugin_dir': rec.plugin_dir,
            }

    # ================= 安装 =================
    def install_zip(self, zip_bytes):
        """安装插件 zip 包（zip 内含 manifest.json，顶层目录或直接平铺均可）。"""
        tmpdir = tempfile.mkdtemp(prefix='plug_')
        try:
            with zipfile.ZipFile(__import__('io').BytesIO(zip_bytes)) as z:
                for info in z.infolist():
                    zname = info.filename.replace('\\', '/')
                    if zname.startswith('/') or '..' in zname.split('/'):
                        return False, f'zip 包含非法路径: {info.filename}'
                z.extractall(tmpdir)
            # 找到 manifest.json
            candidates = []
            for root, _, files in os.walk(tmpdir):
                if 'manifest.json' in files:
                    candidates.append(root)
            if not candidates:
                return False, 'zip 中未找到 manifest.json'
            src = min(candidates, key=len)  # 最浅的那个
            with open(os.path.join(src, 'manifest.json'), 'r', encoding='utf-8') as f:
                manifest = json.load(f)
            pid = manifest.get('id') or os.path.basename(src)
            if not manifest.get('id'):
                return False, 'manifest.json 缺少 id 字段'
            if not (pid and all(ch.isalnum() or ch in '-_' for ch in pid) and len(pid) <= 64):
                return False, f'插件 id 非法（仅允许字母数字_-，长度≤64）: {pid}'
            target = os.path.join(self.plugin_dir, pid)
            if os.path.exists(target):
                shutil.rmtree(target, ignore_errors=True)
            shutil.copytree(src, target)
            self.scan()
            self.audit('plugin_installed', pid, 'manager', f'安装 v{manifest.get("version") or "?"}')
            return True, pid
        except Exception as e:
            return False, f'{type(e).__name__}: {e}'
        finally:
            shutil.rmtree(tmpdir, ignore_errors=True)
