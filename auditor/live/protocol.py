#!/usr/bin/env python3
"""Poll Therefore's captured internal Console protocol. Python 3.10+."""
import socket
import ssl
import uuid
import urllib.error
import urllib.request
from xml.etree import ElementTree as ET

from .codec import make_ascii_login_proof

SOAP = 'http://schemas.xmlsoap.org/soap/envelope/'
NS = 'http://tempuri.org/'
ZERO = str(uuid.UUID(int=0))


class ProtocolError(Exception):
    pass


class ResultError(ProtocolError):
    def __init__(self, operation, code):
        self.code = code
        self.operation = operation
        super().__init__(f'{operation} returned {code} (0x{code & 0xffffffff:08X})')


def local(tag):
    return tag.rsplit('}', 1)[-1]


def field(root, name, required=True):
    found = next((e for e in root.iter() if local(e.tag) == name), None)
    if found is None and required:
        raise ProtocolError(f'Missing response field: {name}')
    return '' if found is None else (found.text or '')


def inner_xml(text):
    # ElementTree already unescapes the SOAP string layer. Do not unescape
    # again: doing so would corrupt entity-escaped event text inside the XML.
    try:
        return ET.fromstring(text)
    except ET.ParseError as exc:
        raise ProtocolError('Malformed inner XML payload') from exc


def result(root, method):
    try:
        code = int(field(root, method + 'Result'))
    except ValueError as exc:
        raise ProtocolError('Malformed operation result code') from exc
    if code:
        raise ResultError(method, code)


class Client:
    def __init__(self, config, password):
        self.config = config
        self.password = password  # retained in memory for session renewal
        self.session_id = None
        self.url = config['url'].rstrip('/')
        self.timeout = float(config.get('timeout_seconds', 30))
        self.tls = ssl.create_default_context(cafile=config.get('ca_bundle'))
        # Keep built-in recovery codes even when an older config supplies a list.
        # 0xC0000098 was observed repeatedly after a forced server restart.
        self.invalid_codes = {-1073741614, -1073741672} | set(config.get('session_invalid_codes', []))

    def call(self, method, fields, sec=False):
        envelope = ET.Element(f'{{{SOAP}}}Envelope')
        body = ET.SubElement(envelope, f'{{{SOAP}}}Body')
        operation = ET.SubElement(body, f'{{{NS}}}{method}')
        for name, value in fields:
            ET.SubElement(operation, f'{{{NS}}}{name}').text = str(value)
        request = urllib.request.Request(
            self.url + ('/Sec' if sec else ''),
            data=ET.tostring(envelope, encoding='utf-8'),
            headers={'Content-Type': 'text/xml; charset=utf-8',
                     'SOAPAction': f'"{NS}ITheXMLService/{method}"'},
        )
        class NoRedirect(urllib.request.HTTPRedirectHandler):
            def redirect_request(self, *args, **kwargs):
                return None
        opener = urllib.request.build_opener(NoRedirect(), urllib.request.HTTPSHandler(context=self.tls))
        try:
            response = opener.open(request, timeout=self.timeout)
        except urllib.error.HTTPError as exc:
            # SOAP faults often arrive with HTTP 500; inspect XML below.
            response = exc
        with response:
            content = response.read()
            status = response.code
        try:
            root = ET.fromstring(content)
        except ET.ParseError as exc:
            raise ProtocolError(f'Server returned non-XML content (HTTP {status})') from exc
        if any(local(e.tag) == 'Fault' for e in root.iter()):
            # Avoid dumping response bodies, JWTs, credentials or session IDs.
            raise ProtocolError(f'{method}: SOAP Fault (HTTP {status})')
        if status != 200:
            raise ProtocolError(f'{method}: unexpected HTTP {status}')
        return root

    def params(self, flags, proof='', login=True):
        c = self.config
        root = ET.Element('ConParams')
        values = [('CT', c.get('client_type', 9)),
                  ('CV', c.get('client_version', 587202563)),
                  ('MSV', c.get('min_server_version', 587202560)),
                  ('Tenant', c['tenant'])]
        if login:
            values.append(('U', c['username']))
        values.extend([('P', proof), ('MM', 0)])
        for key, value in values:
            ET.SubElement(root, key).text = str(value)
        node = ET.SubElement(root, 'NodeName')
        ET.SubElement(node, 'I').text = c.get('node', socket.gethostname())
        ET.SubElement(node, 'IP').text = c.get('reported_ip', '0.0.0.0')
        ET.SubElement(root, 'Flags').text = str(flags)
        ET.SubElement(root, 'LCID').text = str(c.get('lcid', 1033))
        return ET.tostring(root, encoding='unicode', short_empty_elements=False)

    def login_fields(self, session, params):
        return [('strTenant', self.config['tenant']),
                ('type', self.config.get('client_type', 9)),
                ('sessionID', session), ('connectResult', ''),
                ('isStreamingAllowed', 'false'), ('retADOS', 0),
                ('retDCOM', 0), ('connectParams', params)]

    def login(self):
        self.session_id = None
        method = 'Connect11Ex'
        pre = self.call(method, [
            ('SessionId', ZERO), ('connectResult', ''),
            ('isStreamingAllowed', 'false'), ('retADOS', 0), ('retDCOM', 0),
            ('strTenant', self.config['tenant']),
            ('type', self.config.get('client_type', 9)),
            ('connectParams', self.params(2, login=False))], sec=True)
        result(pre, method)
        # Captured pre-auth retADOS is nonzero; this is expected before login.
        method = 'Connect11LoginEx'
        challenge_reply = self.call(method, self.login_fields(ZERO, self.params(4)))
        self.check_login_codes(challenge_reply, method)
        provisional = str(uuid.UUID(field(challenge_reply, 'sessionID')))
        if provisional == ZERO:
            raise ProtocolError('Challenge response returned zero session GUID')
        conres = inner_xml(field(challenge_reply, 'connectResult'))
        proof = make_ascii_login_proof(field(conres, 'Chlg'), self.password,
                                      field(conres, 'Key'))
        authenticated = self.call(method, self.login_fields(provisional, self.params(34, proof)))
        self.check_login_codes(authenticated, method)
        session = str(uuid.UUID(field(authenticated, 'sessionID')))
        if session == ZERO:
            raise ProtocolError('Login returned zero session GUID')
        conres = inner_xml(field(authenticated, 'connectResult'))
        if not any(local(e.tag) == 'UserInfo' and len(e) for e in conres.iter()):
            raise ProtocolError('Login did not return authenticated UserInfo')
        self.session_id = session

    @staticmethod
    def check_login_codes(root, method):
        result(root, method)
        for name in ('retADOS', 'retDCOM'):
            code = int(field(root, name))
            if code:
                raise ResultError(method + '/' + name, code)

    def refresh_view(self, view_type, last_id=0):
        reply = self.call('RefreshConsoleView', [
            ('strResultObject', ''), ('sessionID', self.session_id),
            ('nViewType', view_type), ('nLastId', last_id)])
        result(reply, 'RefreshConsoleView')
        payload = field(reply, 'strResultObject')
        if not payload.strip():
            return None
        return inner_xml(payload)

    def poll(self, cursor):
        root = self.refresh_view(3, cursor)
        if root is None:
            return []
        if local(root.tag) != 'Msgs':
            raise ProtocolError('Expected Msgs payload for view 3')
        events = []
        for elem in root:
            if local(elem.tag) != 'Elem':
                continue
            event = {local(child.tag): xml_value(child) for child in elem}
            try:
                event['Key'] = int(event['Key'])
            except (KeyError, ValueError, TypeError) as exc:
                raise ProtocolError('Message lacks a numeric Key; cursor was not advanced') from exc
            events.append(event)
        return sorted(events, key=lambda e: e['Key'])


def xml_value(element):
    if not len(element):
        return element.text or ''
    return {local(child.tag): xml_value(child) for child in element}

