"""Python client for the Docker reference app; all enforcement stays in containers."""
from __future__ import annotations

import secrets
import time
from .prototype.transport import request


class ReferenceApp:
    def __init__(self, url="http://127.0.0.1:8080", *, identity="client", token=None):
        from .prototype.client import credential
        from .prototype.reference import CLIENTS
        if identity not in CLIENTS:
            raise ValueError("Unknown reference-app identity")
        self.url, self.identity = url.rstrip('/'), identity
        self.token = token if token is not None else credential(identity)

    def call(self, operation, body):
        return request(self.url + '/' + operation, self.token, body)

    def ingest(self, text, *, workflow=None, timeout=30):
        workflow = workflow or secrets.token_hex(16)
        self.call('submit', {'id': workflow, 'text': text})
        return self.wait(workflow, timeout)

    def wait(self, workflow, timeout=30):
        deadline = time.monotonic() + timeout
        while time.monotonic() < deadline:
            result = self.read(workflow)
            if result['state'] == 'complete':
                return result
            time.sleep(.1)
        raise RuntimeError(f'Workflow {workflow} is still processing; check status')

    def read(self, workflow):
        return self.call('status', {'id': workflow})

    def replace(self, workflow, version, text):
        return self.call('replace', {'id': workflow, 'version': version, 'text': text})

    def report(self):
        return self.call('report', {})

    def approve(self, targets, *, operation=None, ttl=30):
        return self.call('approve', {'targets': [list(t) for t in targets], 'operation': operation or secrets.token_hex(16), 'ttl': ttl})

    def purge(self, envelope):
        return self.call('purge', envelope)

    def investigate(self, operation):
        return self.call('investigate', {'operation': operation})

    def deploy(self, rules, *, change_id=None):
        return self.call('deploy', {'rules': rules, 'change_id': change_id or secrets.token_hex(16)})

    def telemetry(self, *, detailed=False, after=0, limit=50):
        return self.call('telemetry', {'detailed': detailed, 'after': after, 'limit': limit})

    def audit(self, receipt=None):
        return self.call('audit', {'receipt': receipt})

    def budget(self, *, owner=None, reset=False):
        return self.call('budget', {'owner': owner or self.identity, 'reset': reset})
