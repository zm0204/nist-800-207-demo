"""Real child-process tests for tunnel readiness and ownership, no Kubernetes needed."""
import sys
from pathlib import Path
import httpx
import pytest


def child(tmp_path, body):
    script = tmp_path / 'forward.py'
    script.write_text(body, encoding='utf-8')
    return [sys.executable, '-u', str(script)]


def test_listening_message_does_not_mean_application_ready(tmp_path):
    from scripts.port_forward import PortForward
    command = child(tmp_path, """import http.server
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(503);self.end_headers()
 def log_message(self,*args):pass
s=http.server.HTTPServer(('127.0.0.1',0),Handler)
print(f'Forwarding from 127.0.0.1:{s.server_port} -> 8443',flush=True)
s.serve_forever()
""")
    with PortForward(command) as forward:
        def probe(port):
            return httpx.get(f'http://127.0.0.1:{port}',timeout=.2,trust_env=False).status_code == 200
        with pytest.raises(TimeoutError, match='application readiness'):
            forward.wait_ready(probe, timeout=.5)


def test_ready_waits_for_actual_endpoint_and_reaps_only_owned_process(tmp_path):
    from scripts.port_forward import PortForward
    command = child(tmp_path, """import http.server
class Handler(http.server.BaseHTTPRequestHandler):
 def do_GET(self):
  self.send_response(204);self.end_headers()
 def log_message(self,*args):pass
s=http.server.HTTPServer(('127.0.0.1',0),Handler)
print(f'Forwarding from 127.0.0.1:{s.server_port} -> 8443',flush=True)
s.serve_forever()
""")
    with PortForward(command) as forward:
        forward.wait_ready(lambda port:httpx.get(f'http://127.0.0.1:{port}',timeout=.2,trust_env=False).status_code==204)
        process=forward.process
        assert process.poll() is None
    assert process.poll() is not None


def test_exit_after_listening_is_a_failure_with_stderr_evidence(tmp_path):
    from scripts.port_forward import PortForward
    command=child(tmp_path,"import sys;print('Forwarding from 127.0.0.1:12345 -> 8443',flush=True);print('lost connection to pod',file=sys.stderr,flush=True);sys.exit(1)")
    with PortForward(command) as forward:
        with pytest.raises(RuntimeError,match='lost connection to pod'):
            forward.wait_ready(lambda port:False,timeout=2)


def test_transport_refusal_is_not_readiness(tmp_path):
    from scripts.port_forward import PortForward
    command=child(tmp_path,"import time;print('Forwarding from 127.0.0.1:12345 -> 8443',flush=True);time.sleep(30)")
    def refused(port):raise httpx.ConnectError('refused')
    with PortForward(command) as forward:
        with pytest.raises(TimeoutError,match='ConnectError'):
            forward.wait_ready(refused,timeout=.3)


def test_cancel_during_restart_reaps_replacement_and_does_not_spawn_next(tmp_path):
    import threading
    from scripts.port_forward import PortForward, supervise_forwards
    command=child(tmp_path,"import time;print('Forwarding from 127.0.0.1:12345 -> 8443',flush=True);time.sleep(30)")
    originals=[PortForward(command).__enter__(),PortForward(command).__enter__()]
    owned=[f.process for f in originals]
    for f in originals:
        f.process.terminate();f.process.wait(timeout=5)
    stop=threading.Event();probing=threading.Event()
    def start(index):
        forward=PortForward(command).__enter__();owned.append(forward.process)
        try:
            def not_ready(port):probing.set();return False
            forward.wait_ready(not_ready,cancelled=stop)
        except BaseException:
            forward.__exit__(*sys.exc_info());raise
        return forward
    worker=threading.Thread(target=supervise_forwards,args=(originals,start,stop))
    worker.start()
    try:
        assert probing.wait(3), 'replacement must enter readiness before cancellation'
        stop.set();worker.join(timeout=3)
        assert not worker.is_alive()
        assert len(owned)==3, 'second failed forward must not restart after cancellation'
        assert all(p.poll() is not None for p in owned)
    finally:
        stop.set();worker.join(timeout=5)
        for f in originals:f.__exit__(None,None,None)
