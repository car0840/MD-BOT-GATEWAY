# -*- coding: utf-8 -*-
"""内置插件：评审查询助手（core-review）

演示插件 API 用法：on_message 钩子 + host.send_text / host.http_request。
查询逻辑与网关原有默认逻辑一致，作为插件化迁移的样例。
"""
import re
import json

HELP_TEXT = (
    'SUPERNOVA 评审查询助手使用说明：\n'
    '· 查工单：查询 <工单ID>（例：查询 1001）\n'
    '· 查邮箱：查询 <学员邮箱>（例：查询 user@example.com）\n'
    '· 查 QQ：查 <QQ号>（例：查 123456789）'
)

STATUS_TXT = {'pending': '待评审', 'reviewing': '评审中', 'pass': '已通过', 'fail': '未通过'}
DECISION_TXT = {'pass': '通过', 'fail': '不通过'}


def _clean_content(content):
    return re.sub(r'<@![^>]+>', '', content or '').strip()


def _parse_query(text):
    """返回 (kind, param)；kind in (review_id, email, qq)。"""
    t = text.strip()
    m = re.match(r'^查询\s*(\d+)$', t)
    if m:
        return 'review_id', m.group(1)
    m = re.match(r'^查询\s+([^@\s]+@[^@\s]+\.[^@\s]+)$', t)
    if m:
        return 'email', m.group(1)
    m = re.match(r'^查\s*(\d{5,12})$', t)
    if m:
        return 'qq', m.group(1)
    return None, None


class Plugin:
    def on_ready(self, host):
        host.log('info', 'core-review 已加载 HOTv1 v3 [v2 hot-reload]')

    def on_message(self, host, ctx):
        text = _clean_content(ctx.get('text'))
        if not text:
            return None
        kind, param = _parse_query(text)
        if not kind or not param:
            return HELP_TEXT
        backend = (ctx.get('backend_url') or '').rstrip('/')
        token = ctx.get('internal_token') or ''
        headers = {'Content-Type': 'application/json'}
        if token:
            headers['X-Service-Token'] = token
        resp = host.http_request('POST', f'{backend}/api/qq-bot/query-review',
                                 headers=headers,
                                 data=json.dumps({'kind': kind, 'param': param, 'app_id': ctx.get('bot')}),
                                 timeout=15)
        try:
            body = resp.get('body') or ''
            data = json.loads(body)
        except Exception:
            return '查询服务暂时不可用，请稍后重试。'
        if not data.get('ok'):
            return '查询服务暂时不可用，请稍后重试。'
        reviews = data.get('reviews') or []
        if not reviews:
            return '未查询到相关评审记录。'
        lines = [f'共 {len(reviews)} 条评审记录：']
        for idx, r in enumerate(reviews, 1):
            lines.append(
                f"{idx}. 工单{r.get('id', '')} | {r.get('student_name', '')} | "
                f"{r.get('major_label', '')} | {STATUS_TXT.get(r.get('status'), r.get('status') or '-')} | "
                f"评审:{r.get('examiner_name') or '-'} | "
                f"复核:{r.get('reviewer_name') or '-'} | 结论:{DECISION_TXT.get(r.get('decision'), r.get('decision') or '-')}"
            )
        reply = '\n'.join(lines)
        if len(reply) > 2000:
            reply = reply[:1990] + '…'
        return reply
