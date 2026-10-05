"""Opt-in Console collector and independent security email dispatcher."""
import hashlib
import logging
import signal
import threading
import time
from urllib.parse import urlsplit, urlunsplit

from .. import config
from ..db import connect, migrate
from .protocol import Client, ResultError
from .store import ingest, evaluate
from .rolling import EvaluationCache
from .outbox import dispatch_outbox_batch

log = logging.getLogger(__name__)


def endpoint_for(base_url):
    url = urlsplit(base_url)
    if url.scheme != 'https' or not url.hostname or url.username or url.password or url.query or url.fragment:
        raise ValueError('Console requires an HTTPS server URL without credentials, query or fragment')
    path = url.path.rstrip('/')
    if not path.lower().endswith('/thexmlserver'):
        path += '/TheXMLServer'
    return urlunsplit((url.scheme, url.netloc, path, '', ''))


def lock_key(tenant_id):
    return int.from_bytes(hashlib.sha256(('auditor-live:' + tenant_id).encode()).digest()[:8], 'big', signed=True)


def collect_tenant(settings, tenant_id, stop):
    client = None
    failures = 0
    snapshot_due = True
    last_snapshot = 0
    signature = None
    cache = EvaluationCache()
    while not stop.is_set():
        try:
            with connect(settings.database_url) as conn:
                # Session lock is released on connection loss; do not advance without it.
                with conn.cursor() as cur:
                    cur.execute('SELECT pg_try_advisory_lock(%s) AS owned', (lock_key(tenant_id),))
                    if not cur.fetchone()['owned']:
                        stop.wait(5)
                        continue
                while not stop.is_set():
                    tenant = config.get_tenant(conn, tenant_id)
                    with conn.cursor() as cur:
                        cur.execute('SELECT * FROM live_settings WHERE tenant_id=%s', (tenant_id,))
                        options = cur.fetchone()
                    conn.commit()
                    if not tenant or not tenant.enabled or not options or not options['enabled']:
                        return
                    try:
                        endpoint = endpoint_for(tenant.base_url)
                        new_signature = (endpoint, tenant.username, tenant.password, tenant.tenant_name)
                        if signature != new_signature:
                            client = Client({'url': endpoint, 'tenant': tenant.tenant_name or '',
                                             'username': tenant.username, 'timeout_seconds': 15}, tenant.password)
                            signature = new_signature
                            snapshot_due = True
                        if not client.session_id:
                            client.login()
                            snapshot_due = True
                        with conn.cursor() as cur:
                            cur.execute('SELECT cursor FROM live_state WHERE tenant_id=%s', (tenant_id,))
                            state = cur.fetchone()
                        conn.commit()
                        snapshot = snapshot_due or time.monotonic() - last_snapshot >= 60
                        events = client.poll(0 if snapshot or not state else state['cursor'])
                        with conn.transaction():
                            ingest(conn, tenant_id, endpoint, events, snapshot, tenant.log_tz)
                        # Independent transaction: an evaluation failure cannot lose collected events.
                        with conn.transaction():
                            evaluate(conn, tenant_id, options['retrieval_limit'], options['api_limit'],
                                     cache, settings.dashboard_url if settings else '')
                        if snapshot:
                            last_snapshot = time.monotonic()
                        snapshot_due, failures = False, 0
                        stop.wait(options['poll_interval_seconds'])
                    except Exception as exc:
                        cache.clear()
                        conn.rollback()
                        if isinstance(exc, ResultError) and client and exc.operation == 'RefreshConsoleView' and exc.code in client.invalid_codes:
                            client.session_id = None
                        failures += 1
                        snapshot_due = True
                        # Only class/code, never response bodies, credentials or exception URLs.
                        error = type(exc).__name__
                        if isinstance(exc, ResultError):
                            error += f': {exc.operation} ({exc.code})'
                        with conn.cursor() as cur:
                            cur.execute('''INSERT INTO live_state(tenant_id,endpoint,last_error,gap_since)
                                VALUES (%s,%s,%s,now()) ON CONFLICT(tenant_id) DO UPDATE SET
                                last_error=EXCLUDED.last_error,gap_since=coalesce(live_state.gap_since,now())''',
                                        (tenant_id, tenant.base_url, error))
                        conn.commit()
                        log.warning('Live collection/evaluation failed for %s: %s', tenant_id, error)
                        stop.wait(min(60, 2 ** min(failures, 6)))
        except Exception as exc:
            cache.clear()
            log.warning('Live worker unavailable for %s: %s', tenant_id, type(exc).__name__)
            client, signature = None, None
            snapshot_due = True
            stop.wait(10)


def dispatch_worker(settings, stop):
    while not stop.is_set():
        try:
            with connect(settings.database_url) as conn:
                while not stop.is_set():
                    n = dispatch_outbox_batch(conn, settings, batch_size=10, stop=stop)
                    if n == 0:
                        stop.wait(5)
        except Exception as exc:
            log.warning('Live outbox dispatcher unavailable: %s', type(exc).__name__)
            stop.wait(10)


def serve(settings):
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    with connect(settings.database_url) as conn:
        migrate(conn)
    workers = {}
    dispatcher = threading.Thread(target=dispatch_worker, args=(settings, stop), daemon=True)
    dispatcher.start()
    try:
        while not stop.is_set():
            try:
                with connect(settings.database_url) as conn, conn.cursor() as cur:
                    cur.execute('''SELECT t.id FROM tenants t JOIN live_settings l ON t.id=l.tenant_id
                                   WHERE t.enabled AND l.enabled''')
                    enabled = {r['id'] for r in cur.fetchall()}
                for key, (thread, signal_) in list(workers.items()):
                    if key not in enabled:
                        signal_.set()
                    if not thread.is_alive():
                        del workers[key]
                for key in enabled - workers.keys():
                    worker_stop = threading.Event()
                    thread = threading.Thread(target=collect_tenant, args=(settings,key,worker_stop), daemon=True)
                    workers[key] = (thread, worker_stop)
                    thread.start()
            except Exception as exc:
                log.warning('Live supervisor unavailable: %s', type(exc).__name__)
            stop.wait(10)
    finally:
        for thread, worker_stop in workers.values():
            worker_stop.set()
        for thread, _ in workers.values():
            thread.join(timeout=50)
        dispatcher.join(timeout=10)
