"""Optional Chromium transport for scoped, identity-isolated application flows."""
import os
import time
from pathlib import Path
from urllib.parse import urljoin
from http.cookies import SimpleCookie

from .scope_policy import is_in_scope_url
from .workflow_execution import _origin
from .burp_evidence import _safe_url


class BrowserTransport:
    def __init__(self, identities, scope, *, timeout=10, budget=200, total_seconds=300, interval=0.2):
        try:
            from playwright.sync_api import sync_playwright, Error
        except ImportError:
            raise RuntimeError("Install the browser extra and Chromium to use engine=browser") from None
        self.error_type = Error
        self.identities, self.scope = identities, scope
        self.timeout, self.budget, self.interval = timeout, budget, interval
        self.deadline = time.monotonic() + total_seconds
        self.last = 0
        self.count, self.blocked, self.failed = 0, 0, 0
        self.transactions = []
        self.contexts, self.pages = {}, {}
        self.pending = {}
        self._closing = set()
        self._closed = False
        self._pw = sync_playwright().start()
        self.browser = None
        try:
            self.browser = self._pw.chromium.launch(headless=True)
            for name in identities:
                self.reset(name)
        except BaseException:
            self.close()
            raise

    def _allowed(self, name, url):
        return is_in_scope_url(url, self.scope) and _origin(url) == _origin(self.identities[name]["origin"])

    def _route(self, name, route):
        if name in self._closing:
            try:
                route.abort()
            except self.error_type:
                pass
            return
        failed_before = self.failed
        try:
            self._serve_route(name, route)
        except self.error_type:
            # A request may be cancelled between fetch and fulfill/abort.
            # Never emit raw Playwright errors containing request details.
            if self.failed == failed_before:
                self.failed += 1
            try:
                route.abort()
            except self.error_type:
                pass

    def _serve_route(self, name, route):
        request = route.request
        if not self._allowed(name, request.url) or self.count >= self.budget or time.monotonic() >= self.deadline:
            self.blocked += 1
            route.abort()
            return
        time.sleep(max(0, self.interval - (time.monotonic() - self.last)))
        if time.monotonic() >= self.deadline:
            self.blocked += 1
            route.abort()
            return
        self.count += 1
        self.last = time.monotonic()
        # Fetch one hop only: browser redirect interception can otherwise
        # inherit credential headers across the redirect chain.
        try:
            response = route.fetch(max_redirects=0, timeout=min(self.timeout, max(0.001, self.deadline - time.monotonic())) * 1000)
        except self.error_type:
            self.failed += 1
            self.transactions.append({"identity": name, "url": _safe_url(request.url),
                                      "method": request.method, "resource_type": request.resource_type,
                                      "status": None, "error_type": "network_error"})
            route.abort()
            return
        self.transactions.append({"identity": name, "url": _safe_url(request.url),
                                  "method": request.method, "resource_type": request.resource_type,
                                  "status": response.status})
        location = response.headers.get("location")
        if 300 <= response.status < 400 and location and not self._allowed(name, urljoin(request.url, location)):
            self.blocked += 1
            route.abort()
            return
        route.fulfill(response=response)

    def reset(self, name):
        if self._closed:
            raise RuntimeError("browser transport is closed")
        self._dispose_context(name)
        identity = self.identities[name]
        headers = {}
        cookies = []
        for header, env_name in identity.get("headers_env", {}).items():
            value = os.environ.get(env_name)
            if not value or "\r" in value or "\n" in value or header.lower() in {"host", "proxy-authorization"}:
                raise ValueError("missing or invalid browser credential environment variable")
            if header.lower() == "cookie":
                parsed = SimpleCookie()
                parsed.load(value)
                if not parsed:
                    raise ValueError("invalid browser cookie credential")
                cookies.extend({"name": key, "value": morsel.value, "url": identity["origin"]} for key, morsel in parsed.items())
            else:
                headers[header] = value
        state = identity.get("storage_state")
        if state and not Path(state).is_file():
            raise ValueError("browser storage_state file is missing")
        context = self.browser.new_context(extra_http_headers=headers, storage_state=state,
                                           service_workers="block", accept_downloads=False)
        self.contexts[name] = context
        pending = set()
        self.pending[name] = pending
        context.on("request", lambda request: pending.add(request))
        context.on("requestfinished", lambda request: pending.discard(request))
        context.on("requestfailed", lambda request: pending.discard(request))
        if cookies:
            context.add_cookies(cookies)
        context.set_default_timeout(self.timeout * 1000)
        context.route("**/*", lambda route: self._route(name, route))
        # WebSockets are not HTTP route interceptions; block them explicitly.
        context.route_web_socket("**/*", lambda socket: socket.close())
        page = context.new_page()
        page.on("dialog", lambda dialog: dialog.dismiss())
        self.pages[name] = page

    def __call__(self, name, spec):
        if self._closed:
            raise RuntimeError("browser transport is closed")
        if not self._allowed(name, spec["url"]):
            raise ValueError("browser request outside identity origin/scope")
        if spec.get("method", "GET").upper() != "GET" or "body" in spec:
            raise ValueError("browser transport navigates GET pages; use form actions for mutations")
        if any(k.lower() in {"authorization", "cookie", "host", "proxy-authorization"} for k in spec.get("headers", {})):
            raise ValueError("request headers cannot override identity credentials")
        remaining = self.deadline - time.monotonic()
        if remaining <= 0 or self.count >= self.budget:
            raise RuntimeError("browser network budget exhausted")
        incomplete_before = self.blocked + self.failed
        page = self.pages[name]
        page.set_default_timeout(min(self.timeout, remaining) * 1000)
        page.set_extra_http_headers(spec.get("headers", {}))
        settings = spec.get("browser", {})
        if "wait_for_network_idle" in settings and type(settings["wait_for_network_idle"]) is not bool:
            raise ValueError("wait_for_network_idle must be a boolean")
        main_responses = []
        def observed(response):
            if response.request.is_navigation_request() and response.request.frame == page.main_frame:
                main_responses.append(response)
        page.on("response", observed)
        try:
            response = page.goto(spec["url"], wait_until="domcontentloaded")
            for action in settings.get("actions", []):
                locator = page.locator(action["selector"])
                kind = action["kind"]
                if kind == "fill":
                    value = os.environ.get(action["value_env"]) if "value_env" in action else action.get("value")
                    if value is None:
                        raise ValueError("missing browser form value")
                    locator.fill(str(value))
                elif kind == "click":
                    locator.click()
                elif kind == "check":
                    locator.check()
                elif kind == "select":
                    locator.select_option(str(action["value"]))
                else:
                    raise ValueError("unsupported browser action")
            if settings.get("wait_for"):
                page.locator(settings["wait_for"]).wait_for(state="visible")
            if settings.get("wait_for_network_idle"):
                remaining = self.deadline - time.monotonic()
                if remaining <= 0:
                    raise RuntimeError("browser run deadline exhausted")
                page.wait_for_load_state("networkidle", timeout=min(self.timeout, remaining) * 1000)
            if not self._allowed(name, page.url):
                raise RuntimeError("browser navigation left configured origin")
            captures = {}
            for variable, capture in settings.get("capture_dom", {}).items():
                locator = page.locator(capture["selector"])
                value = locator.get_attribute(capture["attribute"]) if "attribute" in capture else locator.inner_text()
                if value is None:
                    raise ValueError("missing browser capture")
                captures[variable] = value
            body = page.locator(settings.get("body_selector", "body")).inner_text()
            final = main_responses[-1] if main_responses else response
            return {"status": final.status if final else 0, "body": body[:1048576],
                    "headers": {}, "truncated": len(body) > 1048576, "captured": captures,
                    "pending_requests": len(self.pending[name]),
                    "network_incomplete": self.blocked + self.failed > incomplete_before or bool(self.pending[name]),
                    "browser_derived": True}
        except self.error_type:
            raise RuntimeError("browser operation failed or timed out") from None
        finally:
            page.remove_listener("response", observed)

    def summary(self):
        return {"engine": "browser", "network_requests": self.count, "blocked_requests": self.blocked,
                "failed_requests": self.failed,
                "transactions": self.transactions}

    def _dispose_context(self, name):
        context = self.contexts.pop(name, None)
        self.pages.pop(name, None)
        self.pending.pop(name, None)
        if context is None:
            return
        self._closing.add(name)
        try:
            # Removing routing without first disabling traffic would allow
            # application polling to bypass the credential-origin guard.
            context.set_offline(True)
            context.unroute_all(behavior="ignoreErrors")
        except self.error_type:
            pass
        finally:
            try:
                context.close()
            except self.error_type:
                pass
            self._closing.discard(name)

    def close(self):
        if self._closed:
            return
        self._closed = True
        try:
            for name in list(self.contexts):
                self._dispose_context(name)
            if self.browser:
                self.browser.close()
        finally:
            self._pw.stop()
