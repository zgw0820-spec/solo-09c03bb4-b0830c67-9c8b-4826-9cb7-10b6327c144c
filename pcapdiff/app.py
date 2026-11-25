"""Flask web application for dual-ended TCP capture comparison."""

from __future__ import annotations

import os
import re

from flask import (
    Flask,
    abort,
    jsonify,
    render_template,
    request,
    send_from_directory,
    url_for,
)

from . import CATEGORY_LABELS, __version__
from .engine import (
    DEFAULT_PAGE_SIZE,
    create_run_dir,
    default_var_dir,
    get_page,
    get_window_page,
    load_outcome,
    run_analysis,
)
from .sample_data import SAMPLES, build_sample

RUN_ID_RE = re.compile(r"^[0-9a-f]{32}$")

CATEGORY_ALIASES = {
    "captured": "captured", "packet": "captured", "data": "captured",
    "1": "captured", "direct": "captured",
    "acked": "acked_only", "acked_only": "acked_only", "ack": "acked_only",
    "ackonly": "acked_only", "2": "acked_only",
    "missing": "missing", "none": "missing", "no_evidence": "missing",
    "noevidence": "missing", "3": "missing",
}


def _normalize_category(value: str | None) -> str | None:
    if not value:
        return None
    v = value.strip().lower()
    if v in CATEGORY_ALIASES:
        return CATEGORY_ALIASES[v]
    # Chinese label fragments.
    if "抓" in value or "数据包" in value:
        return "captured"
    if "ACK" in value.upper() or "确认" in value:
        return "acked_only"
    if "无证据" in value or "缺失" in value:
        return "missing"
    return None


def _pagination_args() -> tuple[int, int, str | None]:
    values = request.values
    try:
        page = int(values.get("page", values.get("p", 1)))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(values.get(
            "size",
            values.get("page_size",
                       values.get("per_page",
                                  values.get("limit", DEFAULT_PAGE_SIZE)))),
        )
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    category = _normalize_category(
        values.get("cat") or values.get("category") or values.get("type")
    )
    return max(1, page), size, category


def _window_pagination_args() -> tuple[int, int, str | None]:
    values = request.values
    try:
        page = int(values.get(
            "wpage", values.get("wp", values.get("window_page", 1))
        ))
    except (TypeError, ValueError):
        page = 1
    try:
        size = int(values.get(
            "wsize",
            values.get("wpage_size",
                       values.get("wper_page",
                                  values.get("wlimit", DEFAULT_PAGE_SIZE))),
        ))
    except (TypeError, ValueError):
        size = DEFAULT_PAGE_SIZE
    kind = (values.get("wkind") or values.get("wcat") or "").strip().lower()
    if kind not in ("zero", "full"):
        kind = None
    return max(1, page), size, kind


def _safe_window_page(run_dir: str):
    wpage, wsize, wkind = _window_pagination_args()
    try:
        return get_window_page(run_dir, wpage, wsize, wkind)
    except Exception:
        return None

SENDER_FIELDS = ("sender", "sender_file", "send", "file1", "a", "left")
RECEIVER_FIELDS = ("receiver", "receiver_file", "recv", "receive",
                   "file2", "b", "right")


def create_app(var_dir: str | None = None) -> Flask:
    app = Flask(__name__)
    app.config["MAX_CONTENT_LENGTH"] = int(
        os.environ.get("PCAPDIFF_MAX_UPLOAD", str(8 * 1024 ** 3))
    )
    var_dir = var_dir or default_var_dir()
    os.makedirs(os.path.join(var_dir, "runs"), exist_ok=True)
    app.config["VAR_DIR"] = var_dir
    app.config["JSON_AS_ASCII"] = False  # Flask <=2.2 compatibility
    try:
        app.json.ensure_ascii = False    # Flask >=2.3 JSON provider
    except AttributeError:
        pass

    # -- helpers ---------------------------------------------------------
    def _run_url(run_id: str, **params) -> str:
        return url_for("result_page", run_id=run_id, **params)

    def _extract_uploads():
        """Find the two uploaded files across common field naming schemes.

        Returns (sender, receiver).  Handles repeated same-name file parts and
        falls back to file-part order (first = sender) when names give no hint.
        """
        # Flatten every file part in submission order, including repeated
        # fields such as two "file" parts.
        all_files = []
        for key, values in request.files.lists():
            for fs in values:
                if fs is not None and fs.filename:
                    all_files.append((key, fs))

        sender = None
        receiver = None
        for name in SENDER_FIELDS:
            for key, fs in all_files:
                if key == name:
                    sender = fs
                    break
            if sender is not None:
                break
        for name in RECEIVER_FIELDS:
            for key, fs in all_files:
                if key == name:
                    receiver = fs
                    break
            if receiver is not None:
                break

        if sender is None or receiver is None:
            send_hint = ("sender", "send", "src", "client", "left", "file1",
                         "pcap1", "cap1", "-a", "_a")
            recv_hint = ("receiver", "recv", "receive", "dst", "server",
                         "right", "file2", "pcap2", "cap2", "-b", "_b")
            for key, fs in all_files:
                low = key.lower()
                if sender is None and any(h in low for h in send_hint) \
                        and not any(h in low for h in ("recv", "receive")):
                    sender = fs
                if receiver is None and any(h in low for h in recv_hint):
                    receiver = fs

        remaining = [fs for _k, fs in all_files
                     if fs is not sender and fs is not receiver]
        if sender is None and remaining:
            sender = remaining.pop(0)
        if receiver is None and remaining:
            receiver = remaining.pop(0)
        return sender, receiver

    def _save_and_analyze(sender_fs, receiver_fs):
        run_id, run_dir = create_run_dir(app.config["VAR_DIR"])
        s_path = os.path.join(run_dir, "sender-upload.pcap")
        r_path = os.path.join(run_dir, "receiver-upload.pcap")
        sender_fs.save(s_path)
        receiver_fs.save(r_path)
        outcome = run_analysis(
            run_id,
            run_dir,
            s_path,
            r_path,
            sender_name=sender_fs.filename or "sender.pcap",
            receiver_name=receiver_fs.filename or "receiver.pcap",
        )
        return outcome

    # -- pages -----------------------------------------------------------
    @app.get("/healthz")
    def healthz():
        return jsonify(status="ok", version=__version__)

    @app.get("/")
    def index():
        return render_template(
            "index.html",
            samples=SAMPLES,
            categories=CATEGORY_LABELS,
            version=__version__,
        )

    @app.post("/")
    def upload_root():
        return _upload_dispatch()

    @app.post("/analyze")
    def upload_analyze():
        return _upload_dispatch()

    @app.post("/upload")
    def upload_alias():
        return _upload_dispatch()

    @app.post("/compare")
    def compare_alias():
        return _upload_dispatch()

    @app.post("/api/analyze")
    def upload_api():
        return _handle_upload_json()

    @app.post("/api/upload")
    def upload_api_alias():
        return _handle_upload_json()

    @app.post("/api/compare")
    def compare_api_alias():
        return _handle_upload_json()

    def _wants_json() -> bool:
        if request.path.startswith("/api/"):
            return True
        fmt = (request.values.get("format") or "").lower()
        if fmt == "json":
            return True
        best = request.accept_mimetypes.best_match(
            ["application/json", "text/html"], default="text/html"
        )
        return (
            best == "application/json"
            and request.accept_mimetypes["application/json"]
            >= request.accept_mimetypes["text/html"]
        )

    def _upload_dispatch():
        if _wants_json():
            return _handle_upload_json()
        return _handle_upload_html()

    def _handle_upload_html():
        sender_fs, receiver_fs = _extract_uploads()
        if sender_fs is None or receiver_fs is None:
            return render_template(
                "index.html",
                samples=SAMPLES,
                categories=CATEGORY_LABELS,
                version=__version__,
                form_error="请同时选择发端和收端两份 Ethernet PCAP 文件。",
            ), 200
        outcome = _save_and_analyze(sender_fs, receiver_fs)
        if not outcome.ok:
            return render_template(
                "result.html",
                outcome=outcome,
                page_data=None,
                window_page=_safe_window_page(outcome.run_dir),
                categories=CATEGORY_LABELS,
                version=__version__,
            ), 200
        page, size, category = _pagination_args()
        page_data = get_page(outcome.run_dir, page, size, category)
        return render_template(
            "result.html",
            outcome=outcome,
            page_data=page_data,
            window_page=_safe_window_page(outcome.run_dir),
            categories=CATEGORY_LABELS,
            version=__version__,
        ), 200

    def _handle_upload_json():
        sender_fs, receiver_fs = _extract_uploads()
        if sender_fs is None or receiver_fs is None:
            return jsonify(ok=False, errors=["需要两个 PCAP 文件：sender 与 receiver"]), 400
        outcome = _save_and_analyze(sender_fs, receiver_fs)
        if not outcome.ok:
            payload = outcome.to_jsonable()
            payload["window_page"] = _safe_window_page(outcome.run_dir)
            return jsonify(payload), 400
        page, size, category = _pagination_args()
        page_data = get_page(outcome.run_dir, page, size, category)
        payload = outcome.to_jsonable()
        payload["page"] = page_data
        payload["window_page"] = _safe_window_page(outcome.run_dir)
        return jsonify(payload), 200

    @app.get("/sample/<sample_key>")
    def sample_run(sample_key: str):
        if sample_key not in SAMPLES:
            abort(404)
        run_id, run_dir = create_run_dir(app.config["VAR_DIR"])
        s_path, r_path, spec = build_sample(sample_key, run_dir)
        outcome = run_analysis(
            run_id,
            run_dir,
            s_path,
            r_path,
            sender_name=f"sample-{sample_key}-sender.pcap",
            receiver_name=f"sample-{sample_key}-receiver.pcap",
        )
        if request.args.get("format") == "json":
            payload = outcome.to_jsonable()
            if outcome.ok:
                payload["page"] = get_page(run_dir, 1, DEFAULT_PAGE_SIZE)
            payload["window_page"] = _safe_window_page(run_dir)
            return jsonify(payload)
        if not outcome.ok:
            return render_template(
                "result.html", outcome=outcome, page_data=None,
                window_page=_safe_window_page(run_dir),
                categories=CATEGORY_LABELS, version=__version__,
            ), 200
        from flask import redirect
        return redirect(url_for("result_page", run_id=run_id))

    @app.get("/sample")
    def sample_default():
        from flask import redirect
        return redirect(url_for("sample_run", sample_key="basic"))

    @app.get("/api/sample/<sample_key>")
    def sample_api(sample_key: str):
        if sample_key not in SAMPLES:
            abort(404)
        run_id, run_dir = create_run_dir(app.config["VAR_DIR"])
        s_path, r_path, _spec = build_sample(sample_key, run_dir)
        outcome = run_analysis(
            run_id, run_dir, s_path, r_path,
            sender_name=f"sample-{sample_key}-sender.pcap",
            receiver_name=f"sample-{sample_key}-receiver.pcap",
        )
        payload = outcome.to_jsonable()
        if outcome.ok:
            page, size, category = _pagination_args()
            payload["page"] = get_page(run_dir, page, size, category)
        payload["window_page"] = _safe_window_page(run_dir)
        return jsonify(payload), 200 if outcome.ok else 400

    @app.get("/r/<run_id>")
    def result_page(run_id: str):
        return _render_result(run_id)

    # Common URL aliases a caller might guess.
    @app.get("/result/<run_id>")
    def result_page_alias(run_id: str):
        return _render_result(run_id)

    @app.get("/results/<run_id>")
    def results_page_alias(run_id: str):
        return _render_result(run_id)

    def _render_result(run_id: str):
        if not RUN_ID_RE.match(run_id):
            abort(404)
        run_dir = os.path.join(app.config["VAR_DIR"], "runs", run_id)
        outcome = load_outcome(run_dir, run_id)
        if outcome is None:
            abort(404)
        if not outcome.ok:
            return render_template(
                "result.html", outcome=outcome, page_data=None,
                window_page=_safe_window_page(run_dir),
                categories=CATEGORY_LABELS, version=__version__,
            )
        page, size, category = _pagination_args()
        page_data = get_page(run_dir, page, size, category)
        return render_template(
            "result.html",
            outcome=outcome,
            page_data=page_data,
            window_page=_safe_window_page(run_dir),
            categories=CATEGORY_LABELS,
            version=__version__,
        )

    @app.get("/api/r/<run_id>")
    def result_api(run_id: str):
        if not RUN_ID_RE.match(run_id):
            abort(404)
        run_dir = os.path.join(app.config["VAR_DIR"], "runs", run_id)
        outcome = load_outcome(run_dir, run_id)
        if outcome is None:
            abort(404)
        page, size, category = _pagination_args()
        payload = outcome.to_jsonable()
        if outcome.ok:
            page_data = get_page(run_dir, page, size, category)
            payload["page"] = page_data
        payload["window_page"] = _safe_window_page(run_dir)
        return jsonify(payload), 200 if outcome.ok else 400

    @app.get("/api/r/<run_id>/windows")
    def result_windows_api(run_id: str):
        if not RUN_ID_RE.match(run_id):
            abort(404)
        run_dir = os.path.join(app.config["VAR_DIR"], "runs", run_id)
        outcome = load_outcome(run_dir, run_id)
        if outcome is None:
            abort(404)
        wpage, wsize, wkind = _window_pagination_args()
        return jsonify({
            "run_id": run_id,
            "window": outcome.window,
            "window_page": get_window_page(run_dir, wpage, wsize, wkind),
        })

    @app.get("/r/<run_id>/download/<which>")
    def download_pcap(run_id: str, which: str):
        if not RUN_ID_RE.match(run_id) or which not in ("sender", "receiver"):
            abort(404)
        run_dir = os.path.join(app.config["VAR_DIR"], "runs", run_id)
        candidates = {
            "sender": ("sender-upload.pcap", "sender.pcap"),
            "receiver": ("receiver-upload.pcap", "receiver.pcap"),
        }[which]
        for name in candidates:
            if os.path.exists(os.path.join(run_dir, name)):
                return send_from_directory(run_dir, name, as_attachment=True)
        abort(404)

    @app.errorhandler(413)
    def too_large(_e):
        return render_template(
            "index.html",
            samples=SAMPLES,
            categories=CATEGORY_LABELS,
            version=__version__,
            form_error="上传文件超过大小限制（PCAPDIFF_MAX_UPLOAD）。",
        ), 413

    return app
