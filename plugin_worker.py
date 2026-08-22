# -*- coding: utf-8 -*-
"""插件 Worker 子进程 —— 加载并运行单个插件，通过 stdio JSON 行协议与主进程通信。

== 职责 ==
- 读取并校验 manifest.json
- 加载插件入口 main.py（约定接口：Plugin 类 + on_ready/on_message/on_command/on_timer）
- 通过 stdin/stdout JSON 行协议接收事件、回传结果，并代理 host API 请求回主进程

== 协议（本地 IPC，一期 stdio，二期可平移到 socket/HTTP）==
主 -> worker:
  {"op":"load","manifest":{...}}                      # 加载插件
  {"op":"call","hook":"on_message","ctx":{...},"req_id":N}
  {"op":"host_result","req_id":M,"ok":true,"value":...}
  {"op":"shutdown"}
worker -> 主:
  {"op":"ready","ok":true,"error":null}               # load 完成
  {"op":"result","req_id":N,"ok":true,"value":{...},"outbox":[...]}
  {"op":"error","req_id":N,"message":"..."}
  {"op":"host_call","req_id":M,"method":"send_text","args":[...]}

== 约束 ==
插件只能通过 host API 与外部交互；单 worker 单插件，崩溃互不影响。
"""
import os
import sys
import json
import importlib.util
import traceback
import threading
import queue

WORKER_REQ_TIMEOUT = 20  # host_call 反向请求超时（秒）


def _send(obj):
    try:
        sys.stdout.write(json.dumps(obj, ensure_ascii=False) + '\n')
        sys.stdout.flush()
    except Exception:
        pass


class HostError(Exception):
    pass


class Host:
    """注入给插件的受限能力集。所有跨进程能力通过 host_call 回主进程执行。"""

    def __init__(self, worker, manifest):
        self._worker = worker
        self._manifest = manifest
        self._outbox = []  # 待发送消息，随 result 返回主进程统一发送

    def _require(self, perm):
        perms = self._manifest.get('permissions') or []
        if perm not in perms:
            raise HostError(f'缺少权限声明: {perm}（请在 manifest.json 的 permissions 中添加）')

    def send_text(self, bot, target, text):
        """发送消息：bot=app_id，target 可为 {'group_openid':...} 或 {'user_openid':...}"""
        self._require('send_message')
        self._outbox.append({'bot': bot, 'target': target, 'text': text})
        return True

    def http_request(self, method, url, headers=None, data=None, timeout=10, max_size=1_000_000):
        """网络请求（需声明 http 权限）。返回 {'status','headers','body'}"""
        self._require('http')
        return self._worker._host_call('http_request', method=method, url=url,
                                       headers=headers, data=data, timeout=timeout, max_size=max_size)

    def get_bot_list(self):
        return self._worker._host_call('get_bot_list')

    def log(self, level, msg):
        self._worker._host_call('log', level=level, msg=str(msg)[:2000])

    def emit_event(self, name, **data):
        return self._worker._host_call('emit_event', name=name, data=data)

    def consume_outbox(self):
        box, self._outbox = self._outbox, []
        return box


class PluginWorker:
    def __init__(self, plugin_dir, manifest):
        self.plugin_dir = plugin_dir
        self.manifest = manifest
        self.host = None
        self.plugin = None
        self._seq = 0
        self._pending = {}
        self._pending_lock = threading.Lock()

    # ---------- host_call 反向代理 ----------
    def _host_call(self, method, **kwargs):
        with self._pending_lock:
            self._seq += 1
            req_id = self._seq
            ev = threading.Event()
            box = {}
            self._pending[req_id] = (ev, box)
        _send({'op': 'host_call', 'req_id': req_id, 'method': method, 'args': kwargs})
        if not ev.wait(WORKER_REQ_TIMEOUT):
            with self._pending_lock:
                self._pending.pop(req_id, None)
            raise HostError(f'host_call {method} 超时')
        if not box.get('ok'):
            raise HostError(box.get('error') or f'host_call {method} 失败')
        return box.get('value')

    def _on_host_result(self, msg):
        with self._pending_lock:
            item = self._pending.pop(msg.get('req_id'), None)
        if item:
            ev, box = item
            box['ok'] = msg.get('ok', True)
            box['error'] = msg.get('error')
            box['value'] = msg.get('value')
            ev.set()

    # ---------- 插件加载 ----------
    def load(self):
        entry = self.manifest.get('entry') or 'main.py'
        entry_path = os.path.join(self.plugin_dir, entry)
        if not os.path.exists(entry_path):
            raise RuntimeError(f'入口文件不存在: {entry}')
        spec = importlib.util.spec_from_file_location(
            f"plugin_{self.manifest.get('id', 'unknown')}", entry_path)
        if spec is None or spec.loader is None:
            raise RuntimeError('无法加载插件入口')
        mod = importlib.util.module_from_spec(spec)
        sys.modules[spec.name] = mod
        spec.loader.exec_module(mod)
        cls = getattr(mod, 'Plugin', None)
        if cls is None:
            raise RuntimeError('插件未定义 Plugin 类')
        self.host = Host(self, self.manifest)
        self.plugin = cls()
        self.plugin.host = self.host
        # 校验必需钩子
        required = self.manifest.get('hooks') or ['on_message']
        for h in required:
            if not hasattr(self.plugin, h):
                raise RuntimeError(f'插件缺少钩子: {h}')
        if hasattr(self.plugin, 'on_ready'):
            try:
                self.plugin.on_ready(self.host)
            except Exception:
                _send({'op': 'ready', 'ok': True, 'warning': traceback.format_exc()})
        _send({'op': 'ready', 'ok': True, 'error': None})

    def _invoke(self, hook, ctx, req_id):
        try:
            if hook == 'on_timer':
                value = self.plugin.on_timer(ctx) if hasattr(self.plugin, 'on_timer') else None
            else:
                fn = getattr(self.plugin, hook, None)
                value = fn(self.host, ctx) if fn else None
            outbox = self.host.consume_outbox() if self.host else []
            _send({'op': 'result', 'req_id': req_id, 'ok': True,
                   'value': value, 'outbox': outbox})
        except Exception as e:
            _send({'op': 'result', 'req_id': req_id, 'ok': False,
                   'value': None, 'outbox': [],
                   'error': f'{type(e).__name__}: {e}\n{traceback.format_exc()}'})

    # ---------- 主循环 ----------
    def run(self):
        _send({'op': 'spawned', 'ok': True})
        # 后台线程读 stdin：host_result 必须由独立线程处理，
        # 否则 load() 内同步等待 host_call 回执时会阻塞主循环而读不到回执（死锁）。
        q = queue.Queue()

        def _reader():
            for line in sys.stdin:
                line = line.strip()
                if not line:
                    continue
                try:
                    msg = json.loads(line)
                except Exception:
                    continue
                if msg.get('op') == 'host_result':
                    self._on_host_result(msg)
                else:
                    q.put(msg)

        threading.Thread(target=_reader, daemon=True).start()
        while True:
            msg = q.get()
            op = msg.get('op')
            if op == 'load':
                try:
                    self.load()
                except Exception as e:
                    _send({'op': 'ready', 'ok': False,
                           'error': f'{type(e).__name__}: {e}\n{traceback.format_exc()}'})
            elif op == 'call':
                self._invoke(msg.get('hook'), msg.get('ctx') or {}, msg.get('req_id'))
            elif op == 'shutdown':
                break
        _send({'op': 'exited', 'ok': True})


def main():
    plugin_dir = sys.argv[1] if len(sys.argv) > 1 else '.'
    manifest_path = os.path.join(plugin_dir, 'manifest.json')
    try:
        with open(manifest_path, 'r', encoding='utf-8') as f:
            manifest = json.load(f)
    except Exception as e:
        _send({'op': 'spawned', 'ok': False, 'error': f'manifest 读取失败: {e}'})
        return
    # worker 初始不加载，等主进程发 load（避免主进程未就绪时抢先 on_ready）
    w = PluginWorker(plugin_dir, manifest)
    w.run()


if __name__ == '__main__':
    main()
