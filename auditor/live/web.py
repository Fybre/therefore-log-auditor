"""Authenticated shadow-monitoring dashboard and scoped workload approvals."""
import datetime as dt
from zoneinfo import ZoneInfo
from psycopg.types.json import Jsonb

from fastapi import Depends, HTTPException, Request
from fastapi.responses import RedirectResponse
from urllib.parse import urlsplit

from .. import audit, config
from ..web import auth
from .detection import validate_approval


def register(app, db_conn):
    templates = app.state.templates
    templates.env.filters["live_time"] = lambda value, tz: (
        value.astimezone(ZoneInfo(tz)).strftime("%d %b %Y %H:%M:%S") if value else "—")

    def tenant_or_404(conn, tenant_id):
        tenant = config.get_tenant(conn, tenant_id)
        if not tenant:
            raise HTTPException(404, 'Tenant not found')
        return tenant

    def bulk_finding(conn, tenant_id, finding_id):
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM live_findings WHERE tenant_id=%s AND id=%s', (tenant_id, finding_id))
            finding = cur.fetchone()
        if not finding:
            raise HTTPException(404, 'Finding not found')
        if finding['rule_id'] not in ('retrieval_burst', 'api_activity_burst'):
            raise HTTPException(422, 'Workload approvals apply only to bulk retrieval or API activity.')
        return finding

    def check_origin(request):
        origin = request.headers.get('origin')
        if origin and urlsplit(origin).netloc != request.headers.get('host'):
            raise HTTPException(403, 'Cross-origin request rejected')

    @app.get('/admin/tenants/{tenant_id}/live')
    @app.get('/t/{tenant_id}/live/fragment')
    @app.get('/t/{tenant_id}/live')
    def page(request: Request, tenant_id: str, expected: bool = False, from_finding: int | None = None, conn=Depends(db_conn)):
        tenant = tenant_or_404(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM live_settings WHERE tenant_id=%s', (tenant_id,))
            options = cur.fetchone() or {'enabled': False, 'retrieval_limit':100, 'api_limit':500,
                                         'poll_interval_seconds':15}
            cur.execute('SELECT * FROM live_state WHERE tenant_id=%s', (tenant_id,))
            state = cur.fetchone()
            now = dt.datetime.now(dt.timezone.utc)
            stale_after = max(60, 3 * options['poll_interval_seconds'])
            stale = not state or not state['last_poll'] or (now-state['last_poll']).total_seconds() > stale_after
            pending = state['total_messages'] - state['evaluated_messages'] if state else 0
            collection = dict(total=state['total_messages'] if state else 0,
                              last_received=state['last_received'] if state else None,
                              latest_event=state['latest_event'] if state else None)
            cur.execute('''SELECT event_time, received_at, payload, activity FROM live_observations
                           WHERE tenant_id=%s ORDER BY id DESC LIMIT 25''', (tenant_id,))
            messages = cur.fetchall()
            cur.execute('''SELECT * FROM live_findings WHERE tenant_id=%s AND (%s OR NOT expected)
                           ORDER BY last_ts DESC LIMIT 100''', (tenant_id, expected))
            findings = cur.fetchall()
            cur.execute('SELECT * FROM live_approvals WHERE tenant_id=%s ORDER BY id DESC', (tenant_id,))
            approvals = cur.fetchall()
        if not tenant.enabled or not options['enabled']:
            status, status_note = 'Collection disabled', 'Enable collection in tenant configuration to start receiving messages.'
        elif state and state['last_error']:
            status, status_note = 'Collection needs attention', 'The worker reported an error. Previously collected messages remain available below.'
        elif not state or not state['last_poll']:
            status, status_note = 'Waiting for connection', 'Collection is enabled, but the worker has not completed its first successful poll.'
        elif stale:
            status, status_note = 'Connection stale', f'No successful poll in the last {stale_after} seconds. Check the live worker.'
        else:
            status, status_note = 'Connected', ''
        prefill = {}
        source_finding = None
        source_ips = []
        if from_finding is not None and request.url.path.startswith('/admin/'):
            source_finding = bulk_finding(conn, tenant_id, from_finding)
            with conn.cursor() as cur:
                cur.execute('''SELECT DISTINCT activity->>'ip' AS ip FROM live_observations
                    WHERE tenant_id=%s AND id=ANY(%s)''', (tenant_id, source_finding['evidence_ids']))
                ips = [r['ip'] for r in cur.fetchall()]
            source_ips = sorted(ip for ip in ips if ip)
            prefill = dict(name=f"Approved activity — {source_finding['subject']}",
                           username=source_finding['subject'],
                           network=source_ips[0] if len(source_ips) == 1 and None not in ips else '',
                           kind=source_finding['rule_id'].removesuffix('_burst'),
                           starts_at=now.astimezone(ZoneInfo(tenant.display_tz)).isoformat(timespec='seconds'),
                           ends_at=(now+dt.timedelta(hours=1)).astimezone(ZoneInfo(tenant.display_tz)).isoformat(timespec='seconds'),
                           max_count=source_finding['details'].get('count', ''), reason='')
        template = 'admin_live.html' if request.url.path.startswith('/admin/') else 'live.html'
        if request.url.path.endswith('/fragment'):
            template = 'live_results.html'
        return templates.TemplateResponse(request, template, {
            'user': auth.current_user(request), 'tenant': tenant, 'options': options,
            'prefill': prefill, 'source_finding': source_finding, 'source_ips': source_ips,
            'collection': collection, 'messages': messages, 'status': status, 'status_note': status_note,
            'state': state, 'stale': stale, 'pending': pending, 'findings': findings, 'approvals': approvals, 'expected': expected,
            'deployment_warnings': app.state.deployment_warnings, 'static_version': app.state.static_version})

    @app.post('/admin/tenants/{tenant_id}/live/settings')
    @app.post('/t/{tenant_id}/live/settings')
    async def settings(request: Request, tenant_id: str, conn=Depends(db_conn)):
        check_origin(request)
        tenant = tenant_or_404(conn, tenant_id)
        form = await request.form()
        try:
            from .worker import endpoint_for
            endpoint_for(tenant.base_url)
            retrieval, api = int(form['retrieval_limit']), int(form['api_limit'])
            poll_interval = int(form.get('poll_interval_seconds', 15))
            if not 5 <= poll_interval <= 60:
                raise ValueError('Polling interval must be between 5 and 60 seconds.')
            if not all(1 <= n <= 2147483647 for n in (retrieval, api)):
                raise ValueError('Thresholds must be positive integers up to 2147483647.')
        except (ValueError, KeyError) as exc:
            raise HTTPException(422, str(exc))
        enabled = form.get('enabled') == 'on'
        with conn.cursor() as cur:
            cur.execute('''INSERT INTO live_settings(tenant_id,enabled,retrieval_limit,api_limit,poll_interval_seconds)
                VALUES (%s,%s,%s,%s,%s) ON CONFLICT(tenant_id) DO UPDATE SET enabled=EXCLUDED.enabled,
                retrieval_limit=EXCLUDED.retrieval_limit,api_limit=EXCLUDED.api_limit,
                poll_interval_seconds=EXCLUDED.poll_interval_seconds''',
                        (tenant_id, enabled, retrieval, api, poll_interval))
        audit.log_action(conn, auth.current_user(request).username, 'live.settings', tenant_id,
                         {'enabled':enabled, 'retrieval_limit':retrieval, 'api_limit':api,
                          'poll_interval_seconds':poll_interval})
        return RedirectResponse(f'/admin/tenants/{tenant_id}/live', status_code=303)

    @app.post('/admin/tenants/{tenant_id}/live/approvals')
    @app.post('/t/{tenant_id}/live/approvals')
    async def approve(request: Request, tenant_id: str, conn=Depends(db_conn)):
        check_origin(request)
        tenant_or_404(conn, tenant_id)
        form = dict(await request.form())
        source_finding = None
        try:
            values = validate_approval(form)
            if form.get('from_finding'):
                source_finding = bulk_finding(conn, tenant_id, int(form['from_finding']))
                if (values['username'] != source_finding['subject'] or
                        values['kind'] != source_finding['rule_id'].removesuffix('_burst')):
                    raise ValueError('The account and activity must match the selected finding.')
            if form.get('mark_expected') and source_finding is None:
                raise ValueError('Choose a finding before marking it expected.')
        except (ValueError, TypeError) as exc:
            raise HTTPException(422, str(exc))
        actor = auth.current_user(request).username
        with conn.cursor() as cur:
            cur.execute('''INSERT INTO live_approvals
                (tenant_id,name,username,network,kind,starts_at,ends_at,max_count,reason,created_by)
                VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s) RETURNING id''',
                        (tenant_id, values['name'], values['username'], values['network'], values['kind'],
                         values['starts_at'], values['ends_at'], values['max_count'], values['reason'], actor))
            approval_id = cur.fetchone()['id']
            if source_finding and form.get('mark_expected') == 'on':
                # Explicit human review of this episode, separate from future policy matching.
                detail = {**source_finding['details'], 'approval_name': values['name'],
                          'manual_review': {'actor': actor, 'reason': values['reason'],
                                            'at': dt.datetime.now(dt.timezone.utc).isoformat(),
                                            'previous_expected': source_finding['expected']}}
                cur.execute('''UPDATE live_findings SET expected=true, approval_id=%s,
                    details=%s, updated_at=now() WHERE tenant_id=%s AND id=%s''',
                            (approval_id, Jsonb(detail), tenant_id, source_finding['id']))
        audit.log_action(conn, actor, 'live.approval.create', tenant_id, {'id':approval_id, 'from_finding': source_finding['id'] if source_finding else None,
            'marked_expected': bool(source_finding and form.get('mark_expected') == 'on'), **{
            k:str(v) for k,v in values.items()}})
        return RedirectResponse(f'/admin/tenants/{tenant_id}/live', status_code=303)

    @app.post('/admin/tenants/{tenant_id}/live/approvals/{approval_id}/revoke')
    @app.post('/t/{tenant_id}/live/approvals/{approval_id}/revoke')
    def revoke(request: Request, tenant_id: str, approval_id: int, conn=Depends(db_conn)):
        check_origin(request)
        tenant_or_404(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute('''UPDATE live_approvals SET revoked_at=now()
                WHERE tenant_id=%s AND id=%s AND revoked_at IS NULL RETURNING id''', (tenant_id, approval_id))
            if not cur.fetchone():
                raise HTTPException(404, 'Active approval not found')
        audit.log_action(conn, auth.current_user(request).username, 'live.approval.revoke', tenant_id,
                         {'id':approval_id})
        return RedirectResponse(f'/admin/tenants/{tenant_id}/live', status_code=303)

    @app.get('/t/{tenant_id}/live/findings/{finding_id}')
    def evidence(request: Request, tenant_id: str, finding_id: int, conn=Depends(db_conn)):
        tenant = tenant_or_404(conn, tenant_id)
        with conn.cursor() as cur:
            cur.execute('SELECT * FROM live_findings WHERE tenant_id=%s AND id=%s', (tenant_id, finding_id))
            finding = cur.fetchone()
            if not finding:
                raise HTTPException(404, 'Finding not found')
            cur.execute('''SELECT id,event_time,received_at,payload,activity FROM live_observations
                WHERE tenant_id=%s AND id=ANY(%s) ORDER BY event_time,id''', (tenant_id, finding['evidence_ids']))
            rows = cur.fetchall()
        return templates.TemplateResponse(request, 'live_evidence.html', {
            'user':auth.current_user(request), 'tenant':tenant, 'finding':finding, 'rows':rows,
            'deployment_warnings':app.state.deployment_warnings, 'static_version':app.state.static_version})
