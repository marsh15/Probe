import hashlib
import json
import time

import pytest
from starlette.testclient import TestClient

from fixtures_runtime.http import MAX_BIG, MAX_BODY, MAX_HISTORY, create_canary, create_fakehttp


@pytest.fixture
def clients(tmp_path):
    (tmp_path / "literal.txt").write_text("literal fixture")
    routes = tmp_path / "routes.yaml"
    routes.write_text(
        """
collections:
  issues:
    id_field: number
    seed: [{number: 1, title: first}]
routes:
  - {method: GET, path: '/greet/{name}', status: 202, headers: {x-fixture: yes}, body: hello}
  - {method: GET, path: /literal, body_file: literal.txt}
  - {method: POST, path: /create, collection_op: {name: issues, op: create}}
  - {method: GET, path: /delayed, body: wait, latency_ms: 20}
  - {method: GET, path: /faulted, body: ok, fault: {status: 429, retry_after: 2, count: 1}}
""".replace("x-fixture: yes", 'x-fixture: "yes"')
    )
    data, admin = create_fakehttp(routes)
    with TestClient(data) as public, TestClient(admin) as control:
        yield public, control


def test_route_table_literal_latency_and_seed_fault(clients):
    data, _ = clients
    response = data.get("/greet/Ada")
    assert (response.status_code, response.text, response.headers["x-fixture"]) == (
        202,
        "hello",
        "yes",
    )
    assert data.get("/literal").text == "literal fixture"
    start = time.monotonic()
    assert data.get("/delayed").text == "wait"
    assert time.monotonic() - start >= 0.015
    assert data.get("/faulted").status_code == 429
    assert data.get("/faulted").text == "ok"


def test_crud_pagination_autoid_and_reset(clients):
    data, admin = clients
    assert data.post("/create", json={"title": "second"}).json()["number"] == 2
    assert data.post("/c/issues", json={"title": "third"}).status_code == 201
    listing = data.get("/c/issues?page=2&per_page=1").json()
    assert listing == {
        "items": [{"number": 2, "title": "second"}],
        "page": 2,
        "per_page": 1,
        "total": 3,
    }
    assert data.get("/c/issues/2").json()["title"] == "second"
    assert data.put("/c/issues/2", json={"title": "replacement"}).json() == {
        "number": 2,
        "title": "replacement",
    }
    assert data.patch("/c/issues/2", json={"extra": True}).json()["extra"] is True
    assert data.patch("/c/issues/2", json={"number": 9}).status_code == 422
    assert data.post("/c/issues", json={"number": 2}).status_code == 409
    assert data.delete("/c/issues/2").status_code == 204
    assert data.delete("/c/issues/2").status_code == 404
    assert admin.get("/_probe/state").json()["collections"]["issues"][1]["number"] == 3
    assert admin.post("/_probe/reset").status_code == 200
    assert admin.get("/_probe/state").json() == {
        "collections": {"issues": [{"number": 1, "title": "first"}]}
    }
    assert admin.get("/_probe/log").json() == []
    assert data.post("/c/issues", json={}).json()["number"] == 2


def test_log_headers_body_hash_source_and_admin_isolation(clients):
    data, admin = clients
    body = b"fake-secret=simulated-only"
    data.post("/missing", content=body, headers={"traceparent": "00-test", "host": "private.test"})
    record = admin.get("/_probe/log").json()[0]
    assert {"method": record["method"], "host": record["host"], "path": record["path"]} == {
        "method": "POST",
        "host": "private.test",
        "path": "/missing",
    }
    assert record["headers"]["traceparent"] == "00-test"
    assert record["body_sha256"] == hashlib.sha256(body).hexdigest()
    assert record["source_ip"] == "testclient"
    assert "body" not in record
    for endpoint in ("log", "state", "reset", "fault", "hits"):
        assert data.get(f"/_probe/{endpoint}").status_code == 404
        assert data.post(f"/_probe/{endpoint}").status_code == 404
    assert admin.get("/hello.txt").status_code == 404


def test_fault_count_retry_after_and_reset(clients):
    data, admin = clients
    payload = {"route": "/hello.txt", "status": 429, "retry_after": 2, "count": 2}
    assert admin.post("/_probe/fault", json=payload).status_code == 200
    for _ in range(2):
        response = data.get("/hello.txt")
        assert (response.status_code, response.headers["retry-after"]) == (429, "2")
    assert data.get("/hello.txt").text == "probe-public-ok"
    admin.post("/_probe/fault", json=payload)
    admin.post("/_probe/reset")
    assert data.get("/hello.txt").status_code == 200
    assert data.get("/faulted").status_code == 200
    for bad in (
        {**payload, "count": -1},
        {**payload, "count": 10001},
        {**payload, "status": 200},
        {**payload, "route": "bad"},
        {**payload, "retry_after": True},
        {**payload, "extra": 1},
    ):
        assert admin.post("/_probe/fault", json=bad).status_code == 422


def test_builtins_stream_limits_and_validation(clients):
    data, _ = clients
    response = data.get(
        "/redirect?to=http://private.test/c/issues&code=307", follow_redirects=False
    )
    assert (response.status_code, response.headers["location"]) == (
        307,
        "http://private.test/c/issues",
    )
    assert data.get("/big?bytes=130000").content == b"x" * 130000
    assert data.get(f"/big?bytes={MAX_BIG + 1}").status_code == 422
    assert data.get("/json/large?items=3").json() == [{"id": i, "value": "probe"} for i in range(3)]
    for path in (
        "/big?bytes=-1",
        "/big?bytes=nan",
        "/slow?ms=30001",
        "/json/large?items=10001",
        "/redirect?code=200",
        "/c/issues?page=0",
        "/c/issues?per_page=1001",
    ):
        assert data.get(path).status_code == 422
    assert data.post("/c/issues", content="invalid json").status_code == 422
    assert data.post("/c/issues", json=[]).status_code == 422
    assert data.get("/slow?ms=0").status_code == 200


def test_capture_and_request_bounds(clients):
    data, admin = clients
    assert data.post("/c/issues", content=b"x" * (MAX_BODY + 1)).status_code == 413
    assert data.get("/hello.txt", headers={"x-long": "x" * 40000}).status_code == 431
    for _ in range(MAX_HISTORY + 3):
        data.get("/hello.txt")
    logs = admin.get("/_probe/log").json()
    assert len(logs) == MAX_HISTORY
    assert len(json.dumps(logs)) < MAX_HISTORY * 40000
    assert logs[0]["sequence"] < logs[-1]["sequence"]
    assert admin.get(f"/_probe/log?since={logs[-2]['sequence']}").json() == logs[-1:]


@pytest.mark.parametrize(
    "text",
    [
        "routes: not-a-list",
        "collections: []",
        "unknown: 1",
        "routes: [{method: GET, path: /x, body: a, body_file: b}]",
        "routes: [{method: GET, path: /_probe/log, body: a}]",
        "routes: [{method: INVALID, path: /x, body: a}]",
        "routes: [{method: GET, path: '/{x:unknown}', body: a}]",
        'routes: [{method: GET, path: /x, headers: {X: "bad\\nvalue"}, body: a}]',
        "collections: {x: {id_field: id, seed: [{id: 1}, {id: 1}]}}",
        "routes: [{method: GET, path: /x, collection_op: {name: missing, op: list}}]",
    ],
)
def test_route_validation_fails_closed(tmp_path, text):
    path = tmp_path / "routes.yaml"
    path.write_text(text)
    with pytest.raises(ValueError):
        create_fakehttp(path)


def test_body_file_escape_rejected_and_not_reopened_unsafely(tmp_path):
    routes_dir = tmp_path / "routes"
    routes_dir.mkdir()
    outside = tmp_path / "outside"
    outside.write_text("outside")
    path = routes_dir / "routes.yaml"
    (routes_dir / "link").symlink_to(outside)
    for file in ("../outside", str(outside), "link"):
        path.write_text(f"routes: [{{method: GET, path: /x, body_file: '{file}'}}]")
        with pytest.raises(ValueError):
            create_fakehttp(path)
    (routes_dir / "safe").write_text("original")
    path.write_text("routes: [{method: GET, path: /x, body_file: safe}]")
    data, _ = create_fakehttp(path)
    (routes_dir / "safe").unlink()
    (routes_dir / "safe").symlink_to(outside)
    with TestClient(data) as client:
        assert client.get("/x").text == "original"


def test_canary_records_arbitrary_requests_and_separate_admin():
    data, admin = create_canary()
    with TestClient(data) as public, TestClient(admin) as control:
        response = public.put(
            "/arbitrary?a=1", content=b"\x00\xff", headers={"traceparent": "test"}
        )
        assert (response.status_code, response.text) == (200, "probe-canary")
        hit = control.get("/_probe/hits").json()[0]
        assert hit["path"] == "/arbitrary" and hit["headers"]["traceparent"] == "test"
        assert hit["body_sha256"] == hashlib.sha256(b"\x00\xff").hexdigest()
        assert hit["source_ip"] == "testclient"
        assert public.get("/_probe/hits").status_code == 404
        assert control.get("/anything").status_code == 404
        for _ in range(MAX_HISTORY + 1):
            public.get("/")
        assert len(control.get("/_probe/hits").json()) == MAX_HISTORY


def test_fault_pattern_collection_override_and_admin_catchall(tmp_path):
    config = tmp_path / "routes.yaml"
    config.write_text("""
collections: {tasks: {id_field: id, seed: []}}
routes:
  - method: POST
    path: /tasks
    collection_op: {name: tasks, op: create}
    status: 202
    headers: {x-created: fixture}
  - {method: GET, path: '/files/{id}', body: file}
  - {method: GET, path: '/{tail:path}', body: fallback}
""")
    data, admin = create_fakehttp(config)
    with TestClient(data) as public, TestClient(admin) as control:
        response = public.post("/tasks", json={"title": "new"})
        assert response.status_code == 202
        assert response.headers["x-created"] == "fixture"
        assert response.json() == {"id": 1, "title": "new"}
        control.post(
            "/_probe/fault",
            json={"route": "/files/{id}", "status": 429, "retry_after": 2, "count": 1},
        )
        assert public.get("/files/a").status_code == 429
        assert public.get("/files/b").text == "file"
        control.post(
            "/_probe/fault", json={"route": "/files/c", "status": 429, "retry_after": 2, "count": 1}
        )
        assert public.get("/files/c").status_code == 429
        assert public.get("/files/d").text == "file"
        assert public.get("/_probe/state").status_code == 404


def test_path_and_streaming_request_body_bounds(clients):
    data, admin = clients
    assert data.get("/" + "a" * 8193).status_code == 414
    assert data.post("/c/issues", content=iter([b"x" * 700000, b"y" * 700000])).status_code == 413
    assert admin.post("/_probe/fault", content=b"x" * (MAX_BODY + 1)).status_code == 413


def test_autoid_avoids_numeric_string_ids_and_deleted_highwater(tmp_path):
    config = tmp_path / "routes.yaml"
    config.write_text("collections: {tasks: {id_field: id, seed: [{id: '1'}]}}")
    data, _ = create_fakehttp(config)
    with TestClient(data) as public:
        response = public.post("/c/tasks", json={})
        assert response.status_code == 201
        assert response.json()["id"] == 2
        assert public.post("/c/tasks", json={"id": "9"}).status_code == 201
        assert public.delete("/c/tasks/9").status_code == 204
        assert public.post("/c/tasks", json={}).json()["id"] == 10


@pytest.mark.parametrize("endpoint", ["/create", "/c/issues", "/c/issues/1"])
@pytest.mark.parametrize(
    "payload",
    [
        b'{"title":"\\ud800"}',
        b'{"nested":[{"\\udfff":"value"}]}',
        b'{"nested":{"value":["\\ud800"]}}',
        b'{"title":NaN}',
        b'{"title":1e400}',
    ],
)
def test_rejected_json_writes_preserve_state_and_autoids(clients, endpoint, payload):
    data, admin = clients
    before = admin.get("/_probe/state").json()
    methods = ["put", "patch"] if endpoint.endswith("/1") else ["post"]
    for method in methods:
        assert data.request(method, endpoint, content=payload).status_code == 422
        assert admin.get("/_probe/state").json() == before
        assert data.get("/c/issues").json()["items"] == before["collections"]["issues"]
    valid = {"title": "café 😀", "nested": {"🌍": ["日本語"]}}
    created = data.post("/c/issues", json=valid)
    assert created.status_code == 201
    assert created.json() == {**valid, "number": 2}
    assert data.patch("/c/issues/2", json={"title": "🛠"}).status_code == 200
    assert data.put("/c/issues/2", json=valid).json() == {**valid, "number": 2}
    assert admin.get("/_probe/state").status_code == 200


@pytest.mark.parametrize("seed_id", [1, "1", 12, "12"])
def test_autoid_preserves_seed_and_explicit_highwater_until_reset(tmp_path, seed_id):
    config = tmp_path / "routes.yaml"
    config.write_text(
        json.dumps(
            {
                "collections": {
                    "tasks": {"id_field": "id", "seed": [{"id": seed_id}, {"id": "label"}]}
                }
            }
        )
    )
    data, admin = create_fakehttp(config)
    with TestClient(data) as public, TestClient(admin) as control:
        assert public.delete(f"/c/tasks/{seed_id}").status_code == 204
        first = int(seed_id) + 1
        assert public.post("/c/tasks", json={}).json()["id"] == first
        assert public.delete(f"/c/tasks/{first}").status_code == 204
        assert public.post("/c/tasks", json={"id": "50"}).status_code == 201
        assert public.post("/c/tasks", json={"id": 20}).status_code == 201
        assert public.delete("/c/tasks/50").status_code == 204
        assert public.post("/c/tasks", json={}).json()["id"] == 51
        assert control.post("/_probe/reset").status_code == 200
        assert public.delete(f"/c/tasks/{seed_id}").status_code == 204
        assert public.post("/c/tasks", json={}).json()["id"] == first
