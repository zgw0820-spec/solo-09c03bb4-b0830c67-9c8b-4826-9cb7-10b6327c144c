"""Flask HTTP-level tests: upload, sample, pagination, JSON API."""

import io
import os
import re

import pytest

from pcapdiff.app import create_app
from pcapdiff.sample_data import build_sample


@pytest.fixture()
def client(var_dir):
    app = create_app(var_dir=var_dir)
    app.config["TESTING"] = True
    with app.test_client() as c:
        yield c


def _sample_files(var_dir, key="basic"):
    d = os.path.join(var_dir, "sample-src")
    sp, rp, _ = build_sample(key, d)
    return sp, rp


def test_index_renders(client):
    resp = client.get("/")
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "upload-form" in body
    assert "/sample/basic" in body
    assert "/sample/wrap" in body


def test_healthz(client):
    resp = client.get("/healthz")
    assert resp.status_code == 200
    assert resp.get_json()["status"] == "ok"


def test_sample_basic_page(client):
    resp = client.get("/sample/basic", follow_redirects=True)
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "data-testid=\"result-page\"" in body
    assert "收端抓到数据包" in body
    assert "仅被收端累计 ACK 确认" in body
    assert "收端无证据" in body
    # All six expected ranges render on page 1.
    starts = re.findall(r'data-start="(\d+)"', body)
    assert starts[:6] == ["0", "250", "300", "450", "700", "800"]


def test_sample_json(client):
    resp = client.get("/sample/wrap?format=json")
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert [it["start"] for it in data["page"]["items"]] == [0, 80, 120, 200, 220]


def test_upload_multipart_and_result_200(client, var_dir):
    sp, rp = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(rp, "rb") as f2:
        resp = client.post(
            "/",
            data={
                "sender": (io.BytesIO(f1.read()), "sender.pcap"),
                "receiver": (io.BytesIO(f2.read()), "receiver.pcap"),
            },
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "data-testid=\"result-page\"" in body
    assert "1,000" in body  # total bytes formatted


def test_api_analyze_json(client, var_dir):
    sp, rp = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(rp, "rb") as f2:
        resp = client.post(
            "/api/analyze",
            data={
                "sender": (io.BytesIO(f1.read()), "s.pcap"),
                "receiver": (io.BytesIO(f2.read()), "r.pcap"),
            },
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    data = resp.get_json()
    assert data["ok"] is True
    assert data["summary"]["total_bytes"] == 1000
    assert len(data["page"]["items"]) == 6
    run_id = data["run_id"]

    # GET JSON result endpoint.
    resp2 = client.get(f"/api/r/{run_id}?page=1&size=2")
    assert resp2.status_code == 200
    j2 = resp2.get_json()
    assert len(j2["page"]["items"]) == 2
    assert j2["page"]["total_pages"] == 3


def test_missing_file_fields(client):
    resp = client.post("/", data={}, content_type="multipart/form-data")
    assert resp.status_code == 200
    assert "请同时选择" in resp.get_data(as_text=True)


def test_validation_failure_page_explains(client, tmp_path):
    bad = tmp_path / "bad.pcap"
    bad.write_bytes(b"xxxx" * 20)
    good_frames_dir = tmp_path
    from conftest import handshake  # type: ignore
    from pcapdiff.pcap_writer import write_classic_pcap
    good = tmp_path / "good.pcap"
    write_classic_pcap(str(good), handshake())

    with open(bad, "rb") as f1, open(good, "rb") as f2:
        resp = client.post(
            "/analyze",
            data={
                "sender": (io.BytesIO(f1.read()), "bad.pcap"),
                "receiver": (io.BytesIO(f2.read()), "good.pcap"),
            },
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    body = resp.get_data(as_text=True)
    assert "validation-failed" in body
    assert "validation-errors" in body


def test_pagination_many_ranges(client, var_dir):
    """250 alternating 1-byte captured/missing intervals -> many pages."""
    from conftest import (  # type: ignore
        ack_packet,
        data_packet,
        handshake,
    )
    from pcapdiff.engine import create_run_dir, run_analysis, get_page
    n = 250
    s = handshake()
    r = handshake()
    for i in range(n):
        s.append(data_packet(i * 2, 1))
        if i % 2 == 0:
            r.append(data_packet(i * 2, 1))
    run_id, rd = create_run_dir(var_dir)
    sp = os.path.join(rd, "s.pcap")
    rp = os.path.join(rd, "r.pcap")
    from pcapdiff.pcap_writer import write_classic_pcap
    write_classic_pcap(sp, s)
    write_classic_pcap(rp, r)
    out = run_analysis(run_id, rd, sp, rp)
    assert out.ok
    assert out.summary["total_ranges"] == n

    p1 = get_page(rd, 1, 50)
    assert len(p1["items"]) == 50
    assert p1["total_pages"] == 5
    p5 = get_page(rd, 5, 50)
    assert len(p5["items"]) == 50
    # Page 6 clamps to last page.
    p6 = get_page(rd, 6, 50)
    assert p6["page"] == 5

    # Rendered HTML pagination control through the route.
    app = create_app(var_dir=var_dir)
    c = app.test_client()
    resp = c.get(f"/r/{run_id}?page=2&size=20")
    body = resp.get_data(as_text=True)
    assert 'data-testid="pagination"' in body
    assert "<strong>2</strong> / 13 页" in body

    # Category filter only shows missing rows.
    resp = c.get(f"/api/r/{run_id}?cat=missing&size=500")
    j = resp.get_json()
    assert j["page"]["total_ranges"] == n // 2
    assert all(it["category"] == "missing" for it in j["page"]["items"])


def test_unknown_run_404(client):
    assert client.get("/r/" + "f" * 32).status_code == 404
    assert client.get("/r/not-a-id").status_code == 404


def test_arbitrary_field_names_by_order(client, var_dir):
    sp, rp = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(rp, "rb") as f2:
        resp = client.post(
            "/compare",
            data={
                "pcap_one": (io.BytesIO(f1.read()), "a.pcap"),
                "pcap_two": (io.BytesIO(f2.read()), "b.pcap"),
            },
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    assert 'data-testid="result-page"' in resp.get_data(as_text=True)


def test_repeated_file_field(client, var_dir):
    from werkzeug.datastructures import MultiDict
    sp, rp = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(rp, "rb") as f2:
        data = MultiDict([
            ("file", (io.BytesIO(f1.read()), "s.pcap")),
            ("file", (io.BytesIO(f2.read()), "r.pcap")),
        ])
        resp = client.post(
            "/upload",
            data=data,
            content_type="multipart/form-data",
        )
    assert resp.status_code == 200
    assert 'data-testid="result-page"' in resp.get_data(as_text=True)


def test_accept_json_content_negotiation(client, var_dir):
    sp, rp = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(rp, "rb") as f2:
        resp = client.post(
            "/analyze",
            data={
                "sender": (io.BytesIO(f1.read()), "s.pcap"),
                "receiver": (io.BytesIO(f2.read()), "r.pcap"),
            },
            content_type="multipart/form-data",
            headers={"Accept": "application/json"},
        )
    assert resp.status_code == 200
    assert resp.get_json()["ok"] is True


def test_post_result_pagination_links_are_absolute(client, var_dir):
    sp, rp = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(rp, "rb") as f2:
        resp = client.post(
            "/analyze",
            data={
                "sender": (io.BytesIO(f1.read()), "s.pcap"),
                "receiver": (io.BytesIO(f2.read()), "r.pcap"),
                "size": "2",
            },
            content_type="multipart/form-data",
        )
    body = resp.get_data(as_text=True)
    # Pagination anchors must point at /r/<id>, not relative ?page on /analyze.
    assert 'href="/r/' in body
    assert 'href="?page=' not in body


def test_result_alias_route(client):
    resp = client.get("/sample/basic")
    run_id = resp.headers["Location"].rstrip("/").split("/")[-1]
    alias = client.get(f"/result/{run_id}?size=10")
    assert alias.status_code == 200
    assert "segment-row" in alias.get_data(as_text=True)


def test_same_capture_at_both_ends_all_captured(client, var_dir):
    sp, _ = _sample_files(var_dir)
    with open(sp, "rb") as f1, open(sp, "rb") as f2:
        resp = client.post(
            "/api/analyze",
            data={
                "sender": (io.BytesIO(f1.read()), "both.pcap"),
                "receiver": (io.BytesIO(f2.read()), "both.pcap"),
                "size": "10000",
            },
            content_type="multipart/form-data",
        )
    data = resp.get_json()
    assert data["ok"] is True
    assert data["summary"]["categories"]["missing"]["bytes"] == 0
    assert data["summary"]["categories"]["acked_only"]["bytes"] == 0
    assert data["summary"]["categories"]["captured"]["bytes"] == 1000
