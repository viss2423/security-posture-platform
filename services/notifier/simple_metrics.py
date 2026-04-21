import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class SimpleMetrics:
    def __init__(self, service_name: str) -> None:
        self.service_name = service_name
        self._lock = threading.Lock()
        self._counters: dict[str, float] = {}
        self._gauges: dict[str, float] = {}
        self._server_started = False
        self._started_at = time.time()

    def inc_counter(self, name: str, amount: float = 1.0) -> None:
        with self._lock:
            self._counters[name] = self._counters.get(name, 0.0) + float(amount)

    def set_gauge(self, name: str, value: float) -> None:
        with self._lock:
            self._gauges[name] = float(value)

    def render(self) -> str:
        with self._lock:
            counters = dict(self._counters)
            gauges = dict(self._gauges)
        gauges.setdefault("process_uptime_seconds", max(0.0, time.time() - self._started_at))
        lines = [
            "# HELP secplat_service_info Service identity.",
            "# TYPE secplat_service_info gauge",
            f'secplat_service_info{{service="{self.service_name}"}} 1',
        ]
        for name, value in sorted(counters.items()):
            lines.append(f"# TYPE {name} counter")
            lines.append(f"{name} {value}")
        for name, value in sorted(gauges.items()):
            lines.append(f"# TYPE {name} gauge")
            lines.append(f"{name} {value}")
        return "\n".join(lines) + "\n"


def start_metrics_server(metrics: SimpleMetrics, *, port: int, logger) -> None:
    if port <= 0 or metrics._server_started:
        return

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            if self.path != "/metrics":
                self.send_response(404)
                self.end_headers()
                return
            body = metrics.render().encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, format, *args):  # noqa: A003
            return

    server = ThreadingHTTPServer(("0.0.0.0", int(port)), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    metrics._server_started = True
    logger.info("metrics_server_started", extra={"metrics_port": int(port)})
