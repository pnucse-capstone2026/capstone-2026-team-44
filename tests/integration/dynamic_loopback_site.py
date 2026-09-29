"""Deterministic loopback-only browser fixture for Dynamic Discovery tests."""

from __future__ import annotations

from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from threading import Event, Lock, Thread
from urllib.parse import urlsplit


NETWORK_API_KEY_SENTINEL = "sk-NETWORKOBSERVATIONVALUE0123456789"
NETWORK_JWT_SENTINEL = (
    "eyJhbGciOiJub25lIn0.eyJzdWIiOiJuZXR3b3JrLW9ic2VydmF0aW9uIn0."
)


@dataclass(frozen=True, slots=True)
class LoopbackRequest:
    method: str
    path: str
    raw_target: str


@dataclass(frozen=True, slots=True)
class LoopbackPostRequest:
    path: str
    raw_target: str
    content_type: str
    body: bytes


class _QuietThreadingHttpServer(ThreadingHTTPServer):
    daemon_threads = True

    def handle_error(self, request: object, client_address: object) -> None:
        return


class _ServerHandle:
    def __init__(
        self,
        server: _QuietThreadingHttpServer,
        *,
        name: str,
    ) -> None:
        self.server = server
        self.ready = Event()
        self.thread = Thread(
            target=self._serve,
            name=name,
            daemon=True,
        )
        self.closed = False

    def _serve(self) -> None:
        self.ready.set()
        self.server.serve_forever(poll_interval=0.01)

    def start(self) -> None:
        self.thread.start()
        if not self.ready.wait(timeout=1.0):
            self.close()
            raise RuntimeError("loopback server did not become ready")

    def close(self) -> bool:
        if self.closed:
            return not self.thread.is_alive()
        self.closed = True
        errors: list[Exception] = []
        try:
            self.server.shutdown()
        except Exception as exc:  # noqa: BLE001 - continue deterministic cleanup.
            errors.append(exc)
        try:
            self.server.server_close()
        except Exception as exc:  # noqa: BLE001 - continue deterministic cleanup.
            errors.append(exc)
        self.thread.join(timeout=2.0)
        if errors:
            raise RuntimeError("loopback server cleanup failed") from errors[0]
        return not self.thread.is_alive()


class DynamicLoopbackSite:
    """Two loopback servers: one authorized site and one blocked sentinel."""

    def __init__(self) -> None:
        self._lock = Lock()
        self._primary_requests: list[LoopbackRequest] = []
        self._sentinel_requests: list[LoopbackRequest] = []
        self._post_requests: list[LoopbackPostRequest] = []
        self.slow_started = Event()
        self.release_slow = Event()
        self._primary: _ServerHandle | None = None
        self._sentinel: _ServerHandle | None = None
        self.root_url = ""
        self.allowed_script_url = ""
        self.eventsource_url = ""
        self.websocket_url = ""
        self.fetch_xhr_url = ""
        self.network_observation_url = ""
        self.network_observation_script_url = ""
        self.network_observation_style_url = ""
        self.network_observation_fetch_url = ""
        self.network_observation_xhr_url = ""
        self.balanced_fetch_xhr_url = ""
        self.balanced_fetch_xhr_script_url = ""
        self.balanced_fetch_xhr_style_url = ""
        self.network_canonicalization_url = ""
        self.network_canonicalization_script_url = ""
        self.network_canonicalization_style_url = ""
        self.observed_post_json_url = ""
        self.golden_post_e2e_url = ""
        self.unsafe_get_url = ""
        self.autosubmit_url = ""
        self.page_close_url = ""
        self.iframe_url = ""
        self.popup_url = ""
        self.redirect_same_url = ""
        self.redirect_target_url = ""
        self.redirect_relative_script_url = ""
        self.redirect_cross_url = ""
        self.redirect_cross_intermediate_url = ""
        self.location_same_url = ""
        self.location_target_url = ""
        self.location_cross_url = ""
        self.slow_url = ""
        self.websocket_budget_url = ""
        self.rendered_basic_url = ""
        self.rendered_sensitive_url = ""
        self.rendered_poisoned_url = ""
        self.rendered_associated_password_url = ""
        self.rendered_deterministic_url = ""
        self.rendered_large_url = ""
        self.rendered_attribute_large_url = ""
        self.rendered_text_large_url = ""
        self.rendered_noisy_url = ""
        self.simple_cli_page_b_url = ""
        self.navigation_start_url = ""
        self.navigation_page_a_url = ""
        self.navigation_page_b_url = ""
        self.navigation_page_c_url = ""
        self.navigation_redirect_url = ""
        self.navigation_redirect_target_url = ""
        self.navigation_duplicate_redirect_url = ""
        self.navigation_cross_redirect_url = ""
        self.navigation_failure_start_url = ""
        self.navigation_not_found_url = ""
        self.navigation_server_error_url = ""
        self.navigation_good_url = ""
        self.navigation_timeout_url = ""
        self.navigation_sensitive_url = ""
        self.combined_basic_url = ""
        self.combined_sensitive_url = ""
        self.combined_multipage_url = ""
        self.combined_page_a_url = ""
        self.combined_page_b_url = ""
        self.final_e2e_url = ""
        self.final_e2e_follow_url = ""
        self.simple_cli_url = ""
        self.simple_cli_follow_url = ""
        self.sentinel_origin = ""
        self.cleanup_complete = False

    @property
    def primary_requests(self) -> tuple[LoopbackRequest, ...]:
        with self._lock:
            return tuple(self._primary_requests)

    @property
    def sentinel_requests(self) -> tuple[LoopbackRequest, ...]:
        with self._lock:
            return tuple(self._sentinel_requests)

    @property
    def post_requests(self) -> tuple[LoopbackPostRequest, ...]:
        with self._lock:
            return tuple(self._post_requests)

    @property
    def primary_port(self) -> int:
        if self._primary is None:
            raise RuntimeError("loopback site is not started")
        return self._primary.server.server_port

    @property
    def sentinel_port(self) -> int:
        if self._sentinel is None:
            raise RuntimeError("loopback site is not started")
        return self._sentinel.server.server_port

    @property
    def server_threads_alive(self) -> tuple[bool, bool]:
        return (
            self._primary is not None and self._primary.thread.is_alive(),
            self._sentinel is not None and self._sentinel.thread.is_alive(),
        )

    def __enter__(self) -> "DynamicLoopbackSite":
        site = self

        class SentinelHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site._record(site._sentinel_requests, "GET", self.path)
                self._send(500, b"sentinel must not be reached", "text/plain")

            def do_POST(self) -> None:
                site._record(site._sentinel_requests, "POST", self.path)
                self._send(500, b"sentinel must not be reached", "text/plain")

            def do_HEAD(self) -> None:
                site._record(site._sentinel_requests, "HEAD", self.path)
                self._send(500, b"", "text/plain")

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, format: str, *args: object) -> None:
                return

        sentinel_server = _QuietThreadingHttpServer(
            ("127.0.0.1", 0),
            SentinelHandler,
        )
        self._sentinel = _ServerHandle(
            sentinel_server,
            name="vulnspider-dynamic-sentinel",
        )
        self._sentinel.start()
        self.sentinel_origin = f"http://127.0.0.1:{self.sentinel_port}"

        class PrimaryHandler(BaseHTTPRequestHandler):
            def do_GET(self) -> None:
                site._record(site._primary_requests, "GET", self.path)
                route = urlsplit(self.path).path
                if route == "/":
                    html = f"""<!doctype html>
                    <html>
                      <head><meta charset="utf-8"></head>
                      <body>
                        <div id="initial-marker">initial</div>
                        <script src="/allowed.js"></script>
                        <script>
                          const blocked = document.createElement("script");
                          blocked.src = "{site.sentinel_origin}/blocked.js";
                          document.head.appendChild(blocked);
                          window.blockedSocket = new WebSocket(
                            "ws://127.0.0.1:{site.sentinel_port}/socket"
                          );
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/allowed.js":
                    script = b"""
                    const marker = document.createElement("div");
                    marker.id = "dynamic-marker";
                    marker.textContent = "javascript-executed";
                    document.body.appendChild(marker);
                    """
                    self._send(
                        200,
                        script,
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route == "/eventsource":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          let failures = 0;
                          function recordFailure() {{
                            failures += 1;
                            if (failures === 2) {{
                              const marker = document.createElement("div");
                              marker.id = "eventsource-marker";
                              marker.textContent = "both-blocked";
                              document.body.appendChild(marker);
                            }}
                          }}
                          const same = new EventSource("/event-stream");
                          same.onerror = recordFailure;
                          const cross = new EventSource(
                            "{site.sentinel_origin}/event-stream"
                          );
                          cross.onerror = recordFailure;
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/event-stream":
                    self._send(
                        200,
                        b"data: unexpected-transport\n\n",
                        "text/event-stream; charset=utf-8",
                    )
                    return
                if route == "/websocket":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          const same = new WebSocket(
                            "ws://127.0.0.1:{site.primary_port}/same-socket"
                          );
                          const cross = new WebSocket(
                            "ws://127.0.0.1:{site.sentinel_port}/cross-socket"
                          );
                          const marker = document.createElement("div");
                          marker.id = "websocket-marker";
                          marker.textContent = "constructors-attempted";
                          document.body.appendChild(marker);
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/fetch-xhr":
                    html = """<!doctype html>
                    <html>
                      <body>
                        <script>
                          let failures = 0;
                          function recordFailure() {
                            failures += 1;
                            if (failures === 2) {
                              const marker = document.createElement("div");
                              marker.id = "fetch-xhr-marker";
                              marker.textContent = "both-blocked";
                              document.body.appendChild(marker);
                            }
                          }
                          fetch("/fetch-target").catch(recordFailure);
                          const xhr = new XMLHttpRequest();
                          xhr.onerror = recordFailure;
                          xhr.open("GET", "/xhr-target");
                          xhr.send();
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/network-observation":
                    html = """<!doctype html>
                    <html>
                      <head>
                        <meta charset="utf-8">
                        <link rel="icon" href="data:,">
                        <link rel="stylesheet" href="/network-observation.css">
                      </head>
                      <body>
                        <div id="network-observation-started">started</div>
                        <script src="/network-observation.js"></script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/balanced-fetch-xhr":
                    html = """<!doctype html>
                    <html>
                      <head>
                        <meta charset="utf-8">
                        <link rel="icon" href="data:,">
                        <link rel="stylesheet" href="/balanced-fetch-xhr.css">
                      </head>
                      <body>
                        <div id="balanced-started">started</div>
                        <script src="/balanced-fetch-xhr.js"></script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/balanced-fetch-xhr.css":
                    self._send(
                        200,
                        b"#balanced-started { display: block; }",
                        "text/css; charset=utf-8",
                    )
                    return
                if route == "/network-canonicalization":
                    html = """<!doctype html>
                    <html>
                      <head>
                        <meta charset="utf-8">
                        <link rel="icon" href="data:,">
                        <link rel="stylesheet" href="/network-canonicalization.css">
                      </head>
                      <body>
                        <div id="network-canonicalization-started">started</div>
                        <script src="/network-canonicalization.js"></script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/observed-post-json":
                    html = f"""<!doctype html>
                    <html>
                      <head>
                        <meta charset="utf-8">
                        <link rel="icon" href="data:,">
                      </head>
                      <body>
                        <div id="observed-post-json-started">started</div>
                        <script>
                        const jsonHeaders = {{
                          "Content-Type": "application/json; charset=utf-8"
                        }};
                        const attempts = [];
                        attempts.push(fetch("/api/search", {{
                          method: "POST",
                          headers: jsonHeaders,
                          body: JSON.stringify({{
                            keyword: "phone",
                            page: 1
                          }})
                        }}));
                        attempts.push(fetch("/api/secret", {{
                          method: "POST",
                          headers: {{
                            ...jsonHeaders,
                            "Authorization":
                              "Bearer POST_AUTHORIZATION_VALUE_SENTINEL"
                          }},
                          body: JSON.stringify({{
                            password: "POST_PASSWORD_VALUE_SENTINEL",
                            api_key: "POST_API_KEY_VALUE_SENTINEL",
                            token: "POST_TOKEN_VALUE_SENTINEL",
                            jwt:
                              "eyJhbGciOiJub25lIn0.eyJzdWIiOiIxIn0."
                          }})
                        }}));
                        attempts.push(fetch("/api/malformed", {{
                          method: "POST",
                          headers: jsonHeaders,
                          body: '{{"keyword":'
                        }}));
                        attempts.push(fetch("/api/array", {{
                          method: "POST",
                          headers: jsonHeaders,
                          body: '["keyword","page"]'
                        }}));
                        attempts.push(fetch("/api/duplicate", {{
                          method: "POST",
                          headers: jsonHeaders,
                          body: '{{"keyword":"one","keyword":"two"}}'
                        }}));
                        attempts.push(fetch("/api/oversized", {{
                          method: "POST",
                          headers: jsonHeaders,
                          body: JSON.stringify({{field: "x".repeat(17000)}})
                        }}));
                        attempts.push(fetch(
                          "{site.sentinel_origin}/api/off-scope-post",
                          {{
                            method: "POST",
                            headers: jsonHeaders,
                            body: JSON.stringify({{keyword: "off-scope"}})
                          }}
                        ));
                        Promise.allSettled(attempts).then(() => {{
                          const marker = document.createElement("div");
                          marker.id = "observed-post-json-complete";
                          marker.textContent = "attempts-complete";
                          document.body.appendChild(marker);
                        }});
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/golden-post-e2e":
                    html = """<!doctype html>
                    <html>
                      <head>
                        <meta charset="utf-8">
                        <link rel="icon" href="data:,">
                      </head>
                      <body>
                        <div id="golden-post-started">started</div>
                        <script>
                        const jsonHeaders = {
                          "Content-Type": "application/json; charset=utf-8"
                        };
                        const attempts = [
                          fetch("/api/search", {
                            method: "POST",
                            headers: jsonHeaders,
                            body: JSON.stringify({
                              keyword: "phone",
                              page: 1
                            })
                          }),
                          fetch("/cart/add", {
                            method: "POST",
                            headers: jsonHeaders,
                            body: JSON.stringify({
                              product_id: "golden-sku",
                              quantity: 1
                            })
                          }),
                          fetch("/login", {
                            method: "POST",
                            headers: jsonHeaders,
                            body: JSON.stringify({
                              username: "golden-post-user",
                              password: "GOLDEN_POST_PASSWORD_SENTINEL"
                            })
                          }),
                          fetch("/graphql", {
                            method: "POST",
                            headers: jsonHeaders,
                            body: JSON.stringify({
                              query: "mutation GoldenAddItem { addItem(id: 1) { id } }",
                              operationName: "GoldenAddItem"
                            })
                          })
                        ];
                        Promise.allSettled(attempts).then(() => {
                          const marker = document.createElement("div");
                          marker.id = "golden-post-complete";
                          marker.textContent = "attempts-complete";
                          document.body.appendChild(marker);
                        });
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/network-canonicalization.css":
                    self._send(
                        200,
                        b"#network-canonicalization-started { display: block; }",
                        "text/css; charset=utf-8",
                    )
                    return
                if route == "/network-canonicalization.js":
                    script = f"""
                    const attempts = [];
                    attempts.push(fetch(
                      "/api/search?keyword=phone&page=1"
                    ));
                    attempts.push(new Promise((resolve) => {{
                      const xhr = new XMLHttpRequest();
                      xhr.onload = resolve;
                      xhr.onerror = resolve;
                      xhr.open(
                        "GET",
                        "/api/filter?category=book&tag=a&tag=b"
                      );
                      xhr.send();
                    }}));
                    attempts.push(fetch(
                      "/api/private?page=1",
                      {{headers: {{
                        "Authorization":
                          "Bearer GET_AUTHORIZATION_CANONICALIZATION_SECRET"
                      }}}}
                    ));
                    attempts.push(fetch(
                      "/api/head?head_secret=HEAD_CANONICALIZATION_SECRET",
                      {{method: "HEAD"}}
                    ));
                    attempts.push(fetch(
                      "/api/post?post_secret=POST_CANONICALIZATION_SECRET",
                      {{
                        method: "POST",
                        headers: {{
                          "Authorization": "Bearer POST_AUTHORIZATION_SECRET"
                        }},
                        body: "POST_BODY_CANONICALIZATION_SECRET"
                      }}
                    ));
                    attempts.push(fetch(
                      "{site.sentinel_origin}/api/off-scope"
                        + "?off_secret=OFF_SCOPE_CANONICALIZATION_SECRET"
                    ));
                    Promise.allSettled(attempts).then(() => {{
                      const marker = document.createElement("div");
                      marker.id = "network-canonicalization-complete";
                      marker.textContent = "attempts-complete";
                      document.body.appendChild(marker);
                    }});
                    """
                    self._send(
                        200,
                        script.encode("utf-8"),
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route in {"/api/search", "/api/filter", "/api/private"}:
                    self._send(200, b"ok", "text/plain; charset=utf-8")
                    return
                if route == "/balanced-fetch-xhr.js":
                    script = f"""
                    const attempts = [];
                    attempts.push(fetch(
                      "/balanced/get-fetch?api_key=GET_FETCH_VALUE_SECRET"
                    ));
                    attempts.push(new Promise((resolve) => {{
                      const xhr = new XMLHttpRequest();
                      xhr.onload = resolve;
                      xhr.onerror = resolve;
                      xhr.open(
                        "GET",
                        "/balanced/get-xhr?session=GET_XHR_VALUE_SECRET"
                      );
                      xhr.send();
                    }}));
                    attempts.push(fetch(
                      "/balanced/head-fetch?token=HEAD_VALUE_SECRET",
                      {{method: "HEAD"}}
                    ));
                    attempts.push(fetch(
                      "/balanced/post-fetch?password=POST_QUERY_VALUE_SECRET",
                      {{
                        method: "POST",
                        headers: {{
                          "Authorization": "Bearer AUTHORIZATION_VALUE_SECRET"
                        }},
                        body: "POST_BODY_VALUE_SECRET"
                      }}
                    ));
                    attempts.push(fetch(
                      "{site.sentinel_origin}/balanced/off-scope"
                        + "?jwt=OFF_SCOPE_VALUE_SECRET"
                    ));
                    attempts.push(fetch("/balanced/redirect-same"));
                    attempts.push(fetch("/balanced/redirect-cross"));
                    Promise.allSettled(attempts).then(() => {{
                      const marker = document.createElement("div");
                      marker.id = "balanced-complete";
                      marker.textContent = "attempts-complete";
                      document.body.appendChild(marker);
                    }});
                    """
                    self._send(
                        200,
                        script.encode("utf-8"),
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route in {
                    "/balanced/get-fetch",
                    "/balanced/get-xhr",
                    "/balanced/redirect-final",
                }:
                    self._send(200, b"ok", "text/plain; charset=utf-8")
                    return
                if route == "/balanced/redirect-same":
                    self._send_redirect("/balanced/redirect-final")
                    return
                if route == "/balanced/redirect-cross":
                    self._send_redirect(
                        site.sentinel_origin + "/balanced/redirect-target"
                    )
                    return
                if route == "/network-observation.js":
                    script = f"""
                    const attempts = [];
                    attempts.push(fetch(
                      "/network-observation/get-fetch"
                        + "?alpha={NETWORK_API_KEY_SENTINEL}"
                        + "&repeat=one&repeat=two"
                    ));
                    attempts.push(new Promise((resolve) => {{
                      const xhr = new XMLHttpRequest();
                      xhr.onload = resolve;
                      xhr.onerror = resolve;
                      xhr.open(
                        "GET",
                        "/network-observation/get-xhr"
                          + "?beta={NETWORK_JWT_SENTINEL}"
                      );
                      xhr.send();
                    }}));
                    attempts.push(fetch(
                      "/network-observation/post-fetch"
                        + "?post_name=POST_QUERY_VALUE_SECRET",
                      {{
                        method: "POST",
                        headers: {{
                          "Content-Type": "application/json",
                          "Authorization": "Bearer AUTHORIZATION_SECRET"
                        }},
                        body: JSON.stringify({{
                          password: "POST_BODY_PASSWORD_SECRET"
                        }})
                      }}
                    ));
                    attempts.push(fetch(
                      "{site.sentinel_origin}/network-observation/off-scope"
                        + "?outside=OFF_SCOPE_QUERY_SECRET"
                    ));
                    Promise.allSettled(attempts).then(() => {{
                      const marker = document.createElement("div");
                      marker.id = "network-observation-complete";
                      marker.textContent = "complete";
                      document.body.appendChild(marker);
                    }});
                    """
                    self._send(
                        200,
                        script.encode("utf-8"),
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route == "/network-observation.css":
                    self._send(
                        200,
                        b"#network-observation-started { display: block; }",
                        "text/css; charset=utf-8",
                    )
                    return
                if route in {
                    "/network-observation/get-fetch",
                    "/network-observation/get-xhr",
                }:
                    self._send(200, b"ok", "text/plain; charset=utf-8")
                    return
                if route == "/unsafe-get":
                    self._send(
                        200,
                        (
                            b"<html><body><script>"
                            b"window.location.replace('/state-change');"
                            b"</script></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/autosubmit":
                    self._send(
                        200,
                        (
                            b"<html><body>"
                            b"<form id='unsafe-form' method='post' "
                            b"action='/submit-target'>"
                            b"<input name='safe' value='fixture'>"
                            b"</form><script>"
                            b"document.getElementById('unsafe-form').requestSubmit();"
                            b"</script></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/page-close":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='page-close-marker'>"
                            b"ready-to-close</div></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/iframe":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <iframe id="same-frame" src="/frame-child"></iframe>
                        <iframe
                          id="cross-frame"
                          src="{site.sentinel_origin}/frame-child"
                        ></iframe>
                        <iframe id="about-frame" src="about:blank"></iframe>
                        <iframe
                          id="replacement-frame"
                          srcdoc="<p>replacement-document</p>"
                        ></iframe>
                        <script>
                          window.addEventListener("load", () => {{
                            document.querySelectorAll("iframe").forEach(
                              (frame) => frame.remove()
                            );
                            const marker = document.createElement("div");
                            marker.id = "iframe-marker";
                            marker.textContent = "children-blocked";
                            document.body.appendChild(marker);
                          }});
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/frame-child":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='child-marker'>"
                            b"unexpected-child</div></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/popup":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          const popup = window.open("about:blank", "_blank");
                          if (popup !== null) {{
                            popup.location.href =
                              "{site.sentinel_origin}/popup-target";
                          }}
                          const marker = document.createElement("div");
                          marker.id = "popup-marker";
                          marker.textContent = "popup-attempted";
                          document.body.appendChild(marker);
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/redirect-same":
                    self._send_redirect("/redirect/final")
                    return
                if route == "/redirect/final":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='redirect-marker'>"
                            b"same-authority</div>"
                            b"<script src='relative.js'></script>"
                            b"</body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/redirect/relative.js":
                    self._send(
                        200,
                        (
                            b"const marker = document.createElement('div');"
                            b"marker.id = 'redirect-relative-marker';"
                            b"marker.textContent = 'target-relative';"
                            b"document.body.appendChild(marker);"
                        ),
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route == "/redirect-cross":
                    self._send_redirect("/redirect/intermediate")
                    return
                if route == "/redirect/intermediate":
                    self._send_redirect(
                        f"{site.sentinel_origin}/redirect-target"
                    )
                    return
                if route == "/location-same":
                    self._send(
                        200,
                        (
                            b"<html><body><script>"
                            b"window.location.replace('/location-target');"
                            b"</script></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/location-target":
                    self._send(
                        200,
                        (
                            b"<html><body><div id='location-marker'>"
                            b"same-authority</div></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/location-cross":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          window.location.replace(
                            "{site.sentinel_origin}/location-target"
                          );
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/websocket-budget":
                    html = f"""<!doctype html>
                    <html>
                      <body>
                        <script>
                          for (let index = 0; index < 1000; index += 1) {{
                            new WebSocket(
                              "ws://127.0.0.1:{site.sentinel_port}/budget-" +
                              index
                            );
                          }}
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/start":
                    html = f"""<!doctype html>
                    <html><body>
                      <a href="/navigation/page-b">page b</a>
                      <a href="/navigation/a-redirect">redirect</a>
                      <a href="/navigation/z-redirect-duplicate">duplicate redirect</a>
                      <a href="/navigation/cross-redirect">cross redirect</a>
                      <a href="/delete">unauthorized state change</a>
                      <a href="{site.sentinel_origin}/outside">outside</a>
                      <script>
                        const first = document.createElement("a");
                        first.href = "/navigation/page-a#first";
                        first.id = "navigation-js-anchor";
                        document.body.appendChild(first);
                        const duplicate = document.createElement("a");
                        duplicate.href = "/navigation/page-a#duplicate";
                        document.body.appendChild(duplicate);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/page-a":
                    html = """<!doctype html>
                    <html><body>
                      <a href="/navigation/page-c">page c</a>
                      <a href="/navigation/start">cycle</a>
                      <script>
                        const form = document.createElement("form");
                        form.action = "/navigation/search";
                        form.method = "get";
                        form.innerHTML =
                          '<input name="from_a" value="dynamic-a">';
                        document.body.appendChild(form);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/page-b":
                    self._send(
                        200,
                        (
                            b"<html><body>"
                            b"<a href='/navigation/page-c?variant=1'></a>"
                            b"<a href='/navigation/start#cycle'></a>"
                            b"</body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/page-c":
                    html = """<!doctype html>
                    <html><body>
                      <form action="/navigation/final-search" method="get">
                        <input name="from_c" value="dynamic-c">
                      </form>
                      <script>
                        const sensitive = document.createElement("form");
                        sensitive.action = "/state-change";
                        sensitive.method = "post";
                        sensitive.innerHTML = `
                          <input name="user" value="NAV_SECRET_SENTINEL_4c2a">
                          <input type="password" name="password"
                            value="NAV_SECRET_SENTINEL_4c2a">
                        `;
                        document.body.appendChild(sensitive);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/a-redirect":
                    self._send_redirect("/navigation/z-redirect-target")
                    return
                if route == "/navigation/z-redirect-target":
                    self._send(
                        200,
                        b"<html><body><a href='/navigation/start'></a></body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/z-redirect-duplicate":
                    self._send_redirect("/navigation/page-a")
                    return
                if route == "/navigation/cross-redirect":
                    self._send_redirect(
                        f"{site.sentinel_origin}/navigation-redirect-target"
                    )
                    return
                if route == "/navigation/failure-start":
                    self._send(
                        200,
                        (
                            b"<html><body>"
                            b"<a href='/navigation/404'></a>"
                            b"<a href='/navigation/500'></a>"
                            b"<a href='/navigation/good'></a>"
                            b"<a href='/navigation/z-timeout'></a>"
                            b"</body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/404":
                    self._send(
                        404,
                        b"<html><body>not found</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/500":
                    self._send(
                        500,
                        b"<html><body>server error</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/good":
                    self._send(
                        200,
                        (
                            b"<html><body><form action='/navigation/good-search' "
                            b"method='get'><input name='after_failure' value='ok'>"
                            b"</form></body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/z-timeout":
                    site.slow_started.set()
                    site.release_slow.wait(timeout=5.0)
                    self._send(
                        200,
                        b"<html><body>late</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/navigation/sensitive":
                    html = """<!doctype html>
                    <html><body>
                      <a href="/navigation/page-a"></a>
                      <form action="/navigation/safe" method="get">
                        <input name="safe" value="1">
                      </form>
                      <script>
                        const form = document.createElement("form");
                        form.action = "/state-change";
                        form.method = "post";
                        form.innerHTML = `
                          <input name="user" value="NAV_SECRET_SENTINEL_4c2a">
                          <input type="password" name="password"
                            value="NAV_SECRET_SENTINEL_4c2a">
                        `;
                        document.body.appendChild(form);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/combined/basic":
                    html = """<!doctype html>
                    <html><body>
                      <a id="static-only"
                        href="/combined/static-only?static_only=1">static</a>
                      <a href="/combined/shared?shared=1">shared</a>
                      <script>
                        document.querySelector("#static-only").remove();
                        const dynamic = document.createElement("a");
                        dynamic.href = "/combined/dynamic-only?dynamic_only=1";
                        dynamic.textContent = "dynamic";
                        document.body.appendChild(dynamic);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/combined/sensitive":
                    html = """<!doctype html>
                    <html><body>
                      <a href="/combined/collision?q=safe">safe</a>
                      <form action="/combined/collision" method="get">
                        <input type="password" name="q"
                          value="COMBINED_SECRET_SENTINEL_2c91">
                      </form>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/combined/multipage":
                    self._send(
                        200,
                        (
                            b"<html><body>"
                            b"<a href='/combined/page-a'>page a</a>"
                            b"<a href='/combined/page-b'>page b</a>"
                            b"</body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/combined/page-a":
                    html = """<!doctype html>
                    <html><body>
                      <a href="/combined/static-a?static_a=1">static a</a>
                      <script>
                        const dynamic = document.createElement("a");
                        dynamic.href = "/combined/dynamic-a?dynamic_a=1";
                        document.body.appendChild(dynamic);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/combined/page-b":
                    html = """<!doctype html>
                    <html><body>
                      <form action="/combined/shared-search" method="get">
                        <input name="shared_page" value="b">
                      </form>
                      <script>
                        const form = document.createElement("form");
                        form.action = "/combined/dynamic-search";
                        form.method = "get";
                        form.innerHTML =
                          '<input name="dynamic_page" value="b">';
                        document.body.appendChild(form);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/simple-cli":
                    html = """<!doctype html>
                    <html>
                      <head>
                        <link rel="stylesheet" href="/simple-cli.css">
                      </head>
                      <body>
                        <div id="simple-root"></div>
                        <a href="/simple-cli/static?simple_static=source">static</a>
                        <script src="/simple-cli.js"></script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/simple-cli-unsafe":
                    html = """<!doctype html>
                    <html><body>
                      <a href="/logout.php">Logout</a>
                      <a href="/account?action=logout&amp;csrf=LOOPBACK_CSRF_SECRET">
                        Query Logout
                      </a>
                      <a href="/account/profile?profile_id=one">Profile</a>
                      <a href="https://www.youtube.com/watch?v=test">External</a>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/account/profile":
                    self._send(
                        200,
                        b"<html><body>profile</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/logout.php":
                    self.send_response(302)
                    self.send_header("Location", "/login.php")
                    self.end_headers()
                    return
                if route == "/login.php":
                    self._send(
                        200,
                        b"<html><body>login</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/simple-cli.css":
                    self._send(
                        200,
                        b"#simple-root { display: block; }",
                        "text/css; charset=utf-8",
                    )
                    return
                if route == "/simple-cli.js":
                    script = f"""
                    const root = document.querySelector("#simple-root");
                    const anchor = document.createElement("a");
                    anchor.href = "/simple-cli/follow?simple_dynamic=rendered";
                    anchor.textContent = "rendered follow";
                    root.appendChild(anchor);

                    const outside = document.createElement("a");
                    outside.href = "{site.sentinel_origin}/simple-outside";
                    outside.textContent = "outside";
                    root.appendChild(outside);

                    const sensitive = document.createElement("form");
                    sensitive.action = "/simple-sensitive";
                    sensitive.method = "post";
                    sensitive.innerHTML = `
                      <input name="user" value="SIMPLE_SECRET_SENTINEL_51af">
                      <input type="password" name="password"
                        value="SIMPLE_SECRET_SENTINEL_51af">
                    `;
                    root.appendChild(sensitive);

                    fetch(
                      "/simple-allowed-fetch?keyword=phone&page=1"
                    ).catch(() => {{}});
                    const xhr = new XMLHttpRequest();
                    xhr.open(
                      "GET",
                      "/simple-allowed-xhr?category=book&tag=a&tag=b"
                    );
                    xhr.send();
                    fetch(
                      "/simple-allowed-private?page=1",
                      {{headers: {{
                        "Authorization": "Bearer SIMPLE_GET_AUTH_SECRET"
                      }}}}
                    ).catch(() => {{}});
                    fetch("/simple-allowed-head", {{method: "HEAD"}})
                      .catch(() => {{}});
                    fetch("/simple-denied-post-fetch", {{
                      method: "POST",
                      headers: {{"Authorization": "Bearer SIMPLE_AUTH_SECRET"}},
                      body: "SIMPLE_POST_BODY_SECRET"
                    }}).catch(() => {{}});
                    fetch(
                      "{site.sentinel_origin}/simple-denied-offscope-fetch"
                    ).catch(() => {{}});
                    new EventSource("/simple-denied-events");
                    new WebSocket(
                      "ws://127.0.0.1:{site.primary_port}/simple-denied-socket"
                    );

                    const frame = document.createElement("iframe");
                    frame.name = "simple-submit-target";
                    frame.src = "/simple-denied-frame";
                    document.body.appendChild(frame);
                    const submit = document.createElement("form");
                    submit.action = "/simple-denied-post";
                    submit.method = "post";
                    submit.target = "simple-submit-target";
                    document.body.appendChild(submit);
                    submit.submit();

                    window.open("/simple-denied-popup", "simple-popup");
                    const crossScript = document.createElement("script");
                    crossScript.src = "{site.sentinel_origin}/simple-cross.js";
                    document.head.appendChild(crossScript);
                    """
                    self._send(
                        200,
                        script.encode("utf-8"),
                        "application/javascript; charset=utf-8",
                    )
                    return
                if route in {
                    "/simple-allowed-fetch",
                    "/simple-allowed-xhr",
                    "/simple-allowed-private",
                }:
                    self._send(200, b"ok", "text/plain; charset=utf-8")
                    return
                if route == "/simple-cli/follow":
                    html = f"""<!doctype html>
                    <html><body>
                      <form action="/simple-cli/page-a-search" method="get">
                        <input name="page_a_form" value="a">
                      </form>
                      <a href="/simple-cli/page-b?simple_page_b=second#first">
                        page b
                      </a>
                      <a href="/simple-cli/page-b?simple_page_b=second#duplicate">
                        page b duplicate
                      </a>
                      <a href="{site.sentinel_origin}/simple-page-a-outside">
                        outside
                      </a>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/simple-cli/page-b":
                    self._send(
                        200,
                        (
                            b"<html><body>"
                            b"<form action='/simple-cli/page-b-search' method='get'>"
                            b"<input name='page_b_form' value='b'>"
                            b"</form>"
                            b"<a href='/simple-cli#cycle'>cycle</a>"
                            b"</body></html>"
                        ),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/simple-cli/static":
                    self._send(
                        200,
                        b"<html><body>simple static follow</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/final-e2e":
                    html = f"""<!doctype html>
                    <html><body>
                      <a id="static-only"
                        href="/final/static?static_only=source">static</a>
                      <a href="/final/shared?shared=duplicate">shared</a>
                      <a href="/final/repeated?repeat=one&amp;repeat=two&amp;fixed=keep">
                        repeated
                      </a>
                      <a href="/final/probe?probe_target=base&amp;fixed=keep">probe</a>
                      <a href="/final/search?q=safe">safe search</a>
                      <a href="/final-e2e/follow">follow</a>
                      <a href="{site.sentinel_origin}/outside">outside</a>
                      <form action="/final/search" method="get">
                        <input type="password" name="q" value="PW_SENTINEL">
                      </form>
                      <script>
                        document.querySelector("#static-only").remove();
                        const dynamic = document.createElement("a");
                        dynamic.href = "/final/dynamic?dynamic_only=rendered";
                        dynamic.textContent = "dynamic";
                        document.body.appendChild(dynamic);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/final-e2e/follow":
                    html = """<!doctype html>
                    <html><body>
                      <script>
                        const form = document.createElement("form");
                        form.action = "/final/follow-search";
                        form.method = "get";
                        form.innerHTML =
                          '<input name="dynamic_follow" value="page-two">' +
                          '<input name="follow_fixed" value="keep">';
                        document.body.appendChild(form);
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route.startswith("/final/"):
                    body = f"request-target:{self.path}".encode("utf-8")
                    self._send(200, body, "text/plain; charset=utf-8")
                    return
                if route in {"/rendered-basic", "/rendered-deterministic"}:
                    html = """<!doctype html>
                    <html>
                      <body>
                        <a href="/rendered-static?s=1">static anchor</a>
                        <form action="/rendered-static-search" method="get">
                          <input name="static" value="source">
                        </form>
                        <div id="render-root"></div>
                        <iframe srcdoc="<a href='/iframe-only?leak=1'>child</a>"></iframe>
                        <script>
                          const root = document.querySelector("#render-root");
                          const marker = document.createElement("div");
                          marker.id = "rendered-js-marker";
                          marker.textContent = "javascript-rendered";
                          root.appendChild(marker);
                          const anchor = document.createElement("a");
                          anchor.href = "/rendered-target?alpha=1&alpha=2&blank=";
                          anchor.textContent = "dynamic anchor";
                          root.appendChild(anchor);
                          const form = document.createElement("form");
                          form.action = "/rendered-search";
                          form.method = "get";
                          form.innerHTML = `
                            <input type="hidden" name="csrf" value="token">
                            <input type="text" name="query" value="initial">
                            <input type="checkbox" name="choice" value="yes">
                            <input type="checkbox" name="ignored" value="no" checked>
                            <select name="role">
                              <option value="user" selected>User</option>
                              <option value="admin">Admin</option>
                            </select>
                            <textarea name="note">initial note</textarea>
                            <input type="text" name="disabled" value="ignored" disabled>
                            <input type="text" value="unnamed">
                          `;
                          root.appendChild(form);
                          form.elements.query.value = "rendered-value";
                          form.elements.choice.checked = true;
                          form.elements.ignored.checked = false;
                          form.elements.role.value = "admin";
                          form.elements.note.value = "rendered note";
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-sensitive":
                    html = """<!doctype html>
                    <html>
                      <body>
                        <form action="/rendered-safe-form" method="post">
                          <input name="safe" value="1">
                        </form>
                        <script>
                          const safe = document.createElement("a");
                          safe.href = "/rendered-safe?ok=1";
                          document.body.appendChild(safe);
                          const form = document.createElement("form");
                          form.action = "/rendered-safe";
                          form.method = "post";
                          form.innerHTML = `
                            <input name="ok" value="SENSITIVE_SENTINEL_92bd">
                            <input type="PaSsWoRd" name="password"
                              value="SENSITIVE_SENTINEL_92bd">
                            <a href="/inside-sensitive?secret=SENSITIVE_SENTINEL_92bd">
                              hidden anchor
                            </a>
                          `;
                          document.body.appendChild(form);
                        </script>
                      </body>
                    </html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-poisoned":
                    html = """<!doctype html>
                    <html><body>
                      <a href="/rendered-poison-safe?ok=1"></a>
                      <form action="/poisoned-sensitive" method="post">
                        <input name="user" value="POISON_SENTINEL_31ac">
                        <input type="password" name="password"
                          value="POISON_SENTINEL_31ac">
                      </form>
                      <script>
                        const nativeGetAttribute = Element.prototype.getAttribute;
                        Element.prototype.getAttribute = function(name) {
                          const actual = nativeGetAttribute.call(this, name);
                          if (
                            this instanceof HTMLInputElement &&
                            String(name).toLowerCase() === "type" &&
                            String(actual).toLowerCase() === "password"
                          ) {
                            return "text";
                          }
                          return actual;
                        };
                        Array.from = () => [];
                        JSON.stringify = () => "poisoned";
                        window.TextEncoder = function() {
                          this.encode = () => ({length: 0});
                        };
                        window.setTimeout = () => 0;
                      </script>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-associated-password":
                    html = """<!doctype html>
                    <html><body>
                      <form id="physical" action="/physical-sensitive" method="post">
                        <input name="user" value="ASSOCIATED_SENTINEL_8b5e">
                        <input type="password" form="associated" name="password"
                          value="ASSOCIATED_SENTINEL_8b5e">
                      </form>
                      <form id="associated" action="/associated-safe" method="post">
                        <input name="safe" value="1">
                      </form>
                    </body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-attribute-large":
                    html = """<!doctype html>
                    <html><body><script>
                      const anchor = document.createElement("a");
                      anchor.href = "/attribute-limit?value=1";
                      for (let index = 0; index < 20; index += 1) {
                        anchor.setAttribute("data-extra-" + index, "bounded");
                      }
                      document.body.appendChild(anchor);
                    </script></body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-text-large":
                    html = """<!doctype html>
                    <html><body><form action="/text-limit" method="post">
                      <textarea name="note"></textarea>
                    </form><script>
                      document.querySelector("textarea").value = "x".repeat(5000);
                    </script></body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-large":
                    html = """<!doctype html>
                    <html><body><script>
                      for (let index = 0; index < 20; index += 1) {
                        const anchor = document.createElement("a");
                        anchor.href = "/large?index=" + index;
                        document.body.appendChild(anchor);
                      }
                    </script></body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/rendered-noisy":
                    html = """<!doctype html>
                    <html><body><a id="moving" href="/tick?value=0"></a>
                    <script>
                      let tick = 0;
                      setInterval(() => {
                        tick += 1;
                        document.querySelector("#moving").href =
                          "/tick?value=" + tick;
                      }, 10);
                    </script></body></html>"""
                    self._send(
                        200,
                        html.encode("utf-8"),
                        "text/html; charset=utf-8",
                    )
                    return
                if route == "/slow":
                    site.slow_started.set()
                    site.release_slow.wait(timeout=5.0)
                    self._send(
                        200,
                        b"<html><body>released</body></html>",
                        "text/html; charset=utf-8",
                    )
                    return
                self._send(404, b"missing", "text/plain")

            def do_POST(self) -> None:
                content_length = self.headers.get("Content-Length", "0")
                try:
                    body_length = max(0, int(content_length))
                except ValueError:
                    body_length = 0
                body = self.rfile.read(body_length)
                site._record(site._primary_requests, "POST", self.path)
                site._record_post(
                    self.path,
                    content_type=self.headers.get("Content-Type", ""),
                    body=body,
                )
                if urlsplit(self.path).path == "/api/search":
                    try:
                        parsed = json.loads(body)
                    except (json.JSONDecodeError, TypeError, ValueError):
                        self._send(400, b"invalid JSON", "text/plain")
                        return
                    response = json.dumps(
                        parsed,
                        ensure_ascii=True,
                        separators=(",", ":"),
                        sort_keys=True,
                    ).encode("utf-8")
                    self._send(200, response, "application/json")
                    return
                self._send(500, b"POST must not execute", "text/plain")

            def do_HEAD(self) -> None:
                site._record(site._primary_requests, "HEAD", self.path)
                route = urlsplit(self.path).path
                status = (
                    200
                    if route in {
                        "/balanced/head-fetch",
                        "/api/head",
                        "/simple-allowed-head",
                    }
                    else 404
                )
                self._send(status, b"", "text/plain; charset=utf-8")

            def _send(self, status: int, body: bytes, content_type: str) -> None:
                self.send_response(status)
                self.send_header("Content-Type", content_type)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def _send_redirect(self, location: str) -> None:
                self.send_response(302)
                self.send_header("Location", location)
                self.send_header("Content-Length", "0")
                self.end_headers()

            def log_message(self, format: str, *args: object) -> None:
                return

        try:
            primary_server = _QuietThreadingHttpServer(
                ("127.0.0.1", 0),
                PrimaryHandler,
            )
            self._primary = _ServerHandle(
                primary_server,
                name="vulnspider-dynamic-primary",
            )
            self._primary.start()
        except Exception:
            self._sentinel.close()
            raise
        self.root_url = f"http://127.0.0.1:{self.primary_port}/"
        self.allowed_script_url = (
            f"http://127.0.0.1:{self.primary_port}/allowed.js"
        )
        self.eventsource_url = (
            f"http://127.0.0.1:{self.primary_port}/eventsource"
        )
        self.websocket_url = (
            f"http://127.0.0.1:{self.primary_port}/websocket"
        )
        self.fetch_xhr_url = (
            f"http://127.0.0.1:{self.primary_port}/fetch-xhr"
        )
        network_observation_origin = f"http://127.0.0.1:{self.primary_port}"
        self.network_observation_url = (
            network_observation_origin + "/network-observation"
        )
        self.network_observation_script_url = (
            network_observation_origin + "/network-observation.js"
        )
        self.network_observation_style_url = (
            network_observation_origin + "/network-observation.css"
        )
        self.network_observation_fetch_url = (
            network_observation_origin
            + "/network-observation/get-fetch"
            + f"?alpha={NETWORK_API_KEY_SENTINEL}&repeat=one&repeat=two"
        )
        self.network_observation_xhr_url = (
            network_observation_origin
            + f"/network-observation/get-xhr?beta={NETWORK_JWT_SENTINEL}"
        )
        self.balanced_fetch_xhr_url = (
            network_observation_origin + "/balanced-fetch-xhr"
        )
        self.balanced_fetch_xhr_script_url = (
            network_observation_origin + "/balanced-fetch-xhr.js"
        )
        self.balanced_fetch_xhr_style_url = (
            network_observation_origin + "/balanced-fetch-xhr.css"
        )
        self.network_canonicalization_url = (
            network_observation_origin + "/network-canonicalization"
        )
        self.network_canonicalization_script_url = (
            network_observation_origin + "/network-canonicalization.js"
        )
        self.network_canonicalization_style_url = (
            network_observation_origin + "/network-canonicalization.css"
        )
        self.observed_post_json_url = (
            network_observation_origin + "/observed-post-json"
        )
        self.golden_post_e2e_url = (
            network_observation_origin + "/golden-post-e2e"
        )
        self.unsafe_get_url = (
            f"http://127.0.0.1:{self.primary_port}/unsafe-get"
        )
        self.autosubmit_url = (
            f"http://127.0.0.1:{self.primary_port}/autosubmit"
        )
        self.page_close_url = (
            f"http://127.0.0.1:{self.primary_port}/page-close"
        )
        self.iframe_url = f"http://127.0.0.1:{self.primary_port}/iframe"
        self.popup_url = f"http://127.0.0.1:{self.primary_port}/popup"
        self.redirect_same_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect-same"
        )
        self.redirect_target_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect/final"
        )
        self.redirect_relative_script_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect/relative.js"
        )
        self.redirect_cross_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect-cross"
        )
        self.redirect_cross_intermediate_url = (
            f"http://127.0.0.1:{self.primary_port}/redirect/intermediate"
        )
        self.location_same_url = (
            f"http://127.0.0.1:{self.primary_port}/location-same"
        )
        self.location_target_url = (
            f"http://127.0.0.1:{self.primary_port}/location-target"
        )
        self.location_cross_url = (
            f"http://127.0.0.1:{self.primary_port}/location-cross"
        )
        self.slow_url = f"http://127.0.0.1:{self.primary_port}/slow"
        self.websocket_budget_url = (
            f"http://127.0.0.1:{self.primary_port}/websocket-budget"
        )
        self.rendered_basic_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-basic"
        )
        self.rendered_sensitive_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-sensitive"
        )
        self.rendered_poisoned_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-poisoned"
        )
        self.rendered_associated_password_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-associated-password"
        )
        self.rendered_deterministic_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-deterministic"
        )
        self.rendered_large_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-large"
        )
        self.rendered_attribute_large_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-attribute-large"
        )
        self.rendered_text_large_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-text-large"
        )
        self.rendered_noisy_url = (
            f"http://127.0.0.1:{self.primary_port}/rendered-noisy"
        )
        navigation_origin = f"http://127.0.0.1:{self.primary_port}"
        self.navigation_start_url = navigation_origin + "/navigation/start"
        self.navigation_page_a_url = navigation_origin + "/navigation/page-a"
        self.navigation_page_b_url = navigation_origin + "/navigation/page-b"
        self.navigation_page_c_url = navigation_origin + "/navigation/page-c"
        self.navigation_redirect_url = navigation_origin + "/navigation/a-redirect"
        self.navigation_redirect_target_url = (
            navigation_origin + "/navigation/z-redirect-target"
        )
        self.navigation_duplicate_redirect_url = (
            navigation_origin + "/navigation/z-redirect-duplicate"
        )
        self.navigation_cross_redirect_url = (
            navigation_origin + "/navigation/cross-redirect"
        )
        self.navigation_failure_start_url = (
            navigation_origin + "/navigation/failure-start"
        )
        self.navigation_not_found_url = navigation_origin + "/navigation/404"
        self.navigation_server_error_url = navigation_origin + "/navigation/500"
        self.navigation_good_url = navigation_origin + "/navigation/good"
        self.navigation_timeout_url = navigation_origin + "/navigation/z-timeout"
        self.navigation_sensitive_url = (
            navigation_origin + "/navigation/sensitive"
        )
        self.combined_basic_url = navigation_origin + "/combined/basic"
        self.combined_sensitive_url = navigation_origin + "/combined/sensitive"
        self.combined_multipage_url = navigation_origin + "/combined/multipage"
        self.combined_page_a_url = navigation_origin + "/combined/page-a"
        self.combined_page_b_url = navigation_origin + "/combined/page-b"
        self.final_e2e_url = navigation_origin + "/final-e2e"
        self.final_e2e_follow_url = navigation_origin + "/final-e2e/follow"
        self.simple_cli_url = navigation_origin + "/simple-cli"
        self.simple_cli_unsafe_url = navigation_origin + "/simple-cli-unsafe"
        self.simple_cli_follow_url = (
            navigation_origin + "/simple-cli/follow?simple_dynamic=rendered"
        )
        self.simple_cli_page_b_url = (
            navigation_origin + "/simple-cli/page-b?simple_page_b=second"
        )
        return self

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        traceback: object | None,
    ) -> bool:
        try:
            self.close()
        except RuntimeError:
            if exc_type is None:
                raise
        if exc_type is None and not self.cleanup_complete:
            raise RuntimeError("loopback server cleanup did not complete")
        return False

    def close(self) -> None:
        if self.cleanup_complete:
            return
        self.release_slow.set()
        errors: list[RuntimeError] = []
        try:
            primary_closed = self._primary is None or self._primary.close()
        except RuntimeError as exc:
            primary_closed = False
            errors.append(exc)
        try:
            sentinel_closed = self._sentinel is None or self._sentinel.close()
        except RuntimeError as exc:
            sentinel_closed = False
            errors.append(exc)
        self.cleanup_complete = primary_closed and sentinel_closed
        if errors:
            raise RuntimeError("loopback site cleanup failed") from errors[0]

    def _record(
        self,
        log: list[LoopbackRequest],
        method: str,
        path: str,
    ) -> None:
        route = urlsplit(path).path
        with self._lock:
            log.append(
                LoopbackRequest(method=method, path=route, raw_target=path)
            )

    def _record_post(
        self,
        path: str,
        *,
        content_type: str,
        body: bytes,
    ) -> None:
        route = urlsplit(path).path
        with self._lock:
            self._post_requests.append(
                LoopbackPostRequest(
                    path=route,
                    raw_target=path,
                    content_type=content_type,
                    body=body,
                )
            )
