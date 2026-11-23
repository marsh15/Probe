"""Bounded in-memory HTTP fixtures with physically separate control applications."""

import asyncio
import copy
import hashlib
import json
import re
from collections import deque
from pathlib import Path

import yaml
from starlette.applications import Starlette
from starlette.exceptions import HTTPException
from starlette.responses import (
    JSONResponse,
    PlainTextResponse,
    RedirectResponse,
    Response,
    StreamingResponse,
)
from starlette.routing import Route, compile_path

from fixtures_runtime.paths import directory, read_file

MAX_BODY = 1024 * 1024
MAX_BIG = 64 * 1024 * 1024
MAX_HISTORY = 1000
MAX_HEADERS = 32 * 1024
MAX_COLLECTION_BYTES = 8 * 1024 * 1024
METHODS = ["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "TRACE", "CONNECT"]
NAME = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")


def integer(value, low, high):
    if isinstance(value, bool) or not re.fullmatch(r"[0-9]+", str(value)):
        raise ValueError("expected an integer")
    result = int(value)
    if not low <= result <= high:
        raise ValueError(f"integer must be between {low} and {high}")
    return result


def shape(value, allowed, required=()):
    if not isinstance(value, dict) or set(value) - set(allowed) or set(required) - set(value):
        raise ValueError("invalid object fields")
    return value


def encoded(value):
    # Validate the UTF-8 representation used by JSONResponse, including nested keys.
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False, ensure_ascii=False
    ).encode("utf-8")


def json_object(body):
    try:
        value = json.loads(body, parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
        if not isinstance(value, dict):
            raise ValueError("expected a JSON object")
        encoded(value)
        return value
    except (UnicodeError, RecursionError, TypeError) as exc:
        raise ValueError("invalid JSON object") from exc


def fault_spec(value, with_route=False):
    allowed = ["status", "retry_after", "count"] + (["route"] if with_route else [])
    shape(value, allowed, allowed)
    if value["status"] != 429 or isinstance(value["status"], bool):
        raise ValueError("only bounded 429 faults are supported")
    result = {
        "status": 429,
        "retry_after": integer(value["retry_after"], 0, 3600),
        "count": integer(value["count"], 1, 10000),
    }
    if with_route:
        route = value["route"]
        if (
            not isinstance(route, str)
            or not route.startswith("/")
            or len(route) > 2048
            or route.startswith("/_probe")
        ):
            raise ValueError("invalid fault route")
        result["route"] = route
    return result


class Capture:
    """ASGI boundary: validate and hash bounded bodies, retain no body history."""

    def __init__(self, app, state=None):
        self.app, self.state = app, state

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        headers = scope.get("headers", [])
        if sum(len(k) + len(v) for k, v in headers) > MAX_HEADERS or len(headers) > 100:
            await PlainTextResponse("headers too large", 431)(scope, receive, send)
            return
        if len(scope["path"]) > 8192 or len(scope.get("query_string", b"")) > 8192:
            await PlainTextResponse("URI too large", 414)(scope, receive, send)
            return
        body = bytearray()
        try:
            async with asyncio.timeout(10):
                while True:
                    message = await receive()
                    if message["type"] == "http.disconnect":
                        return
                    body.extend(message.get("body", b""))
                    if len(body) > MAX_BODY:
                        await PlainTextResponse("body too large", 413)(scope, receive, send)
                        return
                    if not message.get("more_body", False):
                        break
        except TimeoutError:
            await PlainTextResponse("body timeout", 408)(scope, receive, send)
            return
        scope["fixture_body"] = bytes(body)
        if self.state is not None:
            self.state.sequence += 1
            decoded = {k.decode("latin1"): v.decode("latin1") for k, v in headers}
            self.state.history.append(
                {
                    "sequence": self.state.sequence,
                    "method": scope["method"],
                    "host": decoded.get("host", ""),
                    "path": scope["path"],
                    "headers": decoded,
                    "body_sha256": hashlib.sha256(body).hexdigest(),
                    "source_ip": scope["client"][0] if scope.get("client") else None,
                }
            )
        delivered = False

        async def replay():
            nonlocal delivered
            if not delivered:
                delivered = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, replay, send)


class State:
    def __init__(self, collections=None):
        self.seed = collections or {}
        self.collections = copy.deepcopy(self.seed)
        self.history = deque(maxlen=MAX_HISTORY)
        self.sequence = 0
        self.faults = {}
        self.highwater = self.seed_highwater()

    def seed_highwater(self):
        return {
            name: max(
                (
                    int(row[config["id_field"]])
                    for row in config["seed"]
                    if str(row[config["id_field"]]).isdigit()
                ),
                default=0,
            )
            for name, config in self.seed.items()
        }

    def reset(self):
        self.collections = copy.deepcopy(self.seed)
        self.history.clear()
        self.faults.clear()
        self.highwater = self.seed_highwater()
        # Sequence remains monotonic so cursors do not alias pre-reset requests.

    def collection(self, request, name, op, item_id=None):
        if name not in self.collections:
            raise HTTPException(404)
        config = self.collections[name]
        rows, key = config["seed"], config["id_field"]
        if op == "list":
            page = integer(request.query_params.get("page", 1), 1, 1000000)
            size = integer(request.query_params.get("per_page", 100), 1, 1000)
            return JSONResponse(
                {
                    "items": rows[(page - 1) * size : page * size],
                    "page": page,
                    "per_page": size,
                    "total": len(rows),
                }
            )
        item = next((row for row in rows if str(row[key]) == str(item_id)), None)
        if op == "get":
            if item is None:
                raise HTTPException(404)
            return JSONResponse(item)
        if op == "delete":
            if item is None:
                raise HTTPException(404)
            rows.remove(item)
            return Response(status_code=204)
        value = json_object(request.scope["fixture_body"])
        new_rows = copy.deepcopy(rows)
        if op == "create":
            if len(rows) >= 10000:
                raise HTTPException(413, "collection full")
            if key not in value:
                value[key] = self.highwater[name] + 1
            validate_id(value[key])
            if any(str(row[key]) == str(value[key]) for row in rows):
                raise HTTPException(409)
            new_rows.append(value)
        else:
            if item is None:
                raise HTTPException(404)
            if key in value and value[key] != item[key]:
                raise ValueError("item identity cannot change")
            value = {**item, **value} if op == "patch" else {**value, key: item[key]}
            new_rows[rows.index(item)] = value
        candidate = copy.deepcopy(self.collections)
        candidate[name]["seed"] = new_rows
        if len(encoded(candidate)) > MAX_COLLECTION_BYTES:
            raise HTTPException(413, "collections full")
        # Construct the complete response before committing rows or the ID highwater.
        response = JSONResponse(value, status_code=201 if op == "create" else 200)
        config["seed"] = new_rows
        if str(value[key]).isdigit():
            self.highwater[name] = max(self.highwater.get(name, 0), int(value[key]))
        return response


def validate_id(value):
    if type(value) not in (int, str) or not NAME.fullmatch(str(value)):
        raise ValueError("identity must be a short integer or path-safe string")


def load_routes(path):
    if path is None:
        return {}, []
    path = Path(path).absolute()
    try:
        with directory(path.parent) as fd:
            config = yaml.safe_load(read_file(fd, path.name, MAX_BODY))
        shape(config, ["routes", "collections"])
        collections = config.get("collections", {})
        if not isinstance(collections, dict) or len(collections) > 100:
            raise ValueError("invalid collections")
        for name, collection in collections.items():
            if not isinstance(name, str) or not NAME.fullmatch(name):
                raise ValueError("invalid collection name")
            shape(collection, ["id_field", "seed"], ["id_field", "seed"])
            key = collection["id_field"]
            if (
                not isinstance(key, str)
                or not NAME.fullmatch(key)
                or not isinstance(collection["seed"], list)
                or len(collection["seed"]) > 10000
            ):
                raise ValueError("invalid collection definition")
            ids = set()
            for row in collection["seed"]:
                if not isinstance(row, dict) or key not in row:
                    raise ValueError("seed rows require identities")
                validate_id(row[key])
                if str(row[key]) in ids:
                    raise ValueError("duplicate seed identity")
                ids.add(str(row[key]))
        if len(encoded(collections)) > MAX_COLLECTION_BYTES:
            raise ValueError("seed too large")
        routes = config.get("routes", [])
        if not isinstance(routes, list) or len(routes) > 1000:
            raise ValueError("invalid route list")
        seen = set()
        for route in routes:
            shape(
                route,
                [
                    "method",
                    "path",
                    "status",
                    "headers",
                    "body",
                    "body_file",
                    "collection_op",
                    "latency_ms",
                    "fault",
                ],
                ["method", "path"],
            )
            if route["method"] not in METHODS:
                raise ValueError("invalid method")
            pattern = route["path"]
            if (
                not isinstance(pattern, str)
                or not pattern.startswith("/")
                or len(pattern) > 2048
                or pattern.startswith("/_probe")
            ):
                raise ValueError("invalid route path")
            compile_path(pattern)
            identity = (route["method"], pattern)
            if identity in seen:
                raise ValueError("duplicate route")
            seen.add(identity)
            if sum(k in route for k in ("body", "body_file", "collection_op")) != 1:
                raise ValueError("route requires exactly one response source")
            if "status" in route:
                route["status"] = integer(route["status"], 200, 599)
            route["latency_ms"] = integer(route.get("latency_ms", 0), 0, 30000)
            headers = route.setdefault("headers", {})
            if not isinstance(headers, dict) or len(headers) > 100:
                raise ValueError("invalid response headers")
            for key, value in headers.items():
                if (
                    not isinstance(key, str)
                    or not re.fullmatch(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+", key)
                    or not isinstance(value, str)
                    or any(ord(c) < 32 or ord(c) > 255 or ord(c) == 127 for c in value)
                ):
                    raise ValueError("invalid response header")
            if sum(len(k) + len(v) for k, v in headers.items()) > MAX_HEADERS:
                raise ValueError("response headers too large")
            if "body_file" in route:
                with directory(path.parent) as fd:
                    route["body"] = read_file(fd, route.pop("body_file"), MAX_BODY)
            if "body" in route:
                value = route["body"]
                if not isinstance(value, bytes | str):
                    value = encoded(value)
                    headers.setdefault("content-type", "application/json")
                route["body"] = value.encode() if isinstance(value, str) else value
                if len(route["body"]) > MAX_BODY:
                    raise ValueError("route body too large")
            if "collection_op" in route:
                operation = route["collection_op"]
                shape(operation, ["name", "op"], ["name", "op"])
                if operation["name"] not in collections or operation["op"] not in {
                    "list",
                    "get",
                    "create",
                    "replace",
                    "patch",
                    "delete",
                }:
                    raise ValueError("invalid collection operation")
            if "fault" in route:
                route["fault"] = fault_spec(route["fault"])
        if sum(len(r.get("body", b"")) for r in routes) > MAX_COLLECTION_BYTES:
            raise ValueError("route table too large")
        return collections, routes
    except (OSError, yaml.YAMLError, TypeError, AssertionError, RecursionError, KeyError) as exc:
        raise ValueError("invalid route configuration") from exc


async def invalid_request(request, exc):
    return JSONResponse({"error": "invalid request"}, status_code=422)


def admin_app(state, canary=False):
    async def history(request):
        since = integer(request.query_params.get("since", 0), 0, 2**63 - 1)
        return JSONResponse([row for row in state.history if row["sequence"] > since])

    async def snapshot(request):
        return JSONResponse(
            {"collections": {k: v["seed"] for k, v in sorted(state.collections.items())}}
        )

    async def reset(request):
        state.reset()
        return JSONResponse({"reset": True})

    async def fault(request):
        value = fault_spec(json_object(request.scope["fixture_body"]), with_route=True)
        route = value.pop("route")
        if route not in state.faults and len(state.faults) >= 1000:
            raise ValueError("fault table full")
        state.faults[route] = value
        return JSONResponse({"fault": True})

    routes = [Route("/_probe/hits" if canary else "/_probe/log", history)]
    routes.append(Route("/_probe/reset", reset, methods=["POST"]))
    if not canary:
        routes.extend(
            [Route("/_probe/state", snapshot), Route("/_probe/fault", fault, methods=["POST"])]
        )
    return Capture(
        Starlette(
            routes=routes,
            exception_handlers={ValueError: invalid_request, RecursionError: invalid_request},
        )
    )


def create_fakehttp(routes_path=None):
    collections, configured = load_routes(routes_path)
    state = State(collections)
    for route in configured:
        if "fault" in route:
            state.faults[route["path"]] = route["fault"].copy()

    async def endpoint(request, config=None):
        if request.url.path.startswith("/_probe"):
            raise HTTPException(404)
        route_key = request.url.path
        if config and route_key not in state.faults:
            route_key = config["path"]
        fault = state.faults.get(route_key)
        if fault:
            fault["count"] -= 1
            if fault["count"] == 0:
                del state.faults[route_key]
            return PlainTextResponse(
                "fixture fault", 429, headers={"retry-after": str(fault["retry_after"])}
            )
        if config:
            await asyncio.sleep(config["latency_ms"] / 1000)
            if "collection_op" in config:
                op = config["collection_op"]
                response = state.collection(
                    request, op["name"], op["op"], request.path_params.get("id")
                )
                if "status" in config:
                    response.status_code = config["status"]
                response.headers.update(config["headers"])
                return response
            return Response(config["body"], config.get("status", 200), config["headers"])
        path = request.url.path
        if path == "/hello.txt":
            return PlainTextResponse("probe-public-ok")
        if path == "/redirect":
            code = integer(request.query_params.get("code", 302), 300, 399)
            if code not in {301, 302, 303, 307, 308}:
                raise ValueError("invalid redirect status")
            target = request.query_params.get("to", "/hello.txt")
            if len(target) > 8192 or any(ord(c) < 32 or ord(c) == 127 for c in target):
                raise ValueError("invalid redirect target")
            return RedirectResponse(target, code)
        if path == "/big":
            size = integer(request.query_params.get("bytes", 1024), 0, MAX_BIG)

            async def chunks():
                remaining = size
                while remaining:
                    length = min(remaining, 65536)
                    yield b"x" * length
                    remaining -= length

            return StreamingResponse(
                chunks(),
                media_type="application/octet-stream",
                headers={"content-length": str(size)},
            )
        if path == "/slow":
            await asyncio.sleep(integer(request.query_params.get("ms", 1000), 0, 30000) / 1000)
            return PlainTextResponse("probe-slow-ok")
        if path == "/json/large":
            size = integer(request.query_params.get("items", 1000), 0, 10000)
            return JSONResponse([{"id": i, "value": "probe"} for i in range(size)])
        if "name" in request.path_params:
            item_id = request.path_params.get("id")
            op = {
                "GET": "get" if item_id is not None else "list",
                "HEAD": "get" if item_id is not None else "list",
                "POST": "create",
                "PUT": "replace",
                "PATCH": "patch",
                "DELETE": "delete",
            }[request.method]
            return state.collection(request, request.path_params["name"], op, item_id)
        raise HTTPException(404)

    routes = []
    for config in configured:

        def make_handler(value):
            async def handler(request):
                return await endpoint(request, value)

            return handler

        routes.append(Route(config["path"], make_handler(config), methods=[config["method"]]))
    routes.extend(
        [
            Route(path, endpoint)
            for path in ("/hello.txt", "/redirect", "/big", "/slow", "/json/large")
        ]
    )
    routes.extend(
        [
            Route("/c/{name}", endpoint, methods=["GET", "POST"]),
            Route("/c/{name}/{id}", endpoint, methods=["GET", "PUT", "PATCH", "DELETE"]),
        ]
    )
    # This guard runs before route matching, including configured catch-all routes.
    app = Starlette(
        routes=routes,
        exception_handlers={ValueError: invalid_request, RecursionError: invalid_request},
    )
    return Capture(app, state), admin_app(state)


def create_canary():
    state = State()

    async def hit(request):
        if request.url.path.startswith("/_probe"):
            raise HTTPException(404)
        return PlainTextResponse("probe-canary")

    return Capture(
        Starlette(routes=[Route("/{path:path}", hit, methods=METHODS)]), state
    ), admin_app(state, canary=True)
