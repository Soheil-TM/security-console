#!/usr/bin/env python3
import json
import os
import re
import shutil
import sys
import threading
import urllib.error
import urllib.parse
import urllib.request
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

import docker
from docker.errors import ContainerError, DockerException, ImageNotFound
from flask import Flask, g, jsonify, render_template, request

from security_console.access import can_start_scan, present_scan
from security_console.auth import install_auth, prepare_auth
from security_console.images import image_rows, valid_image_ref
from security_console.trivy import parse_report as parse_trivy_report

app = Flask(__name__)
DATA = Path(os.environ.get("DATA_DIR", "/data"))
HOST_SCAN_DIR = os.environ.get("HOST_SCAN_DIR", "/var/lib/security-scans")
SCAN_DIR = Path(os.environ.get("SCAN_DIR", "/scans"))
SONAR_URL = os.environ.get("SONAR_URL", "http://192.168.205.155:9000")
SONAR_PROJECT_KEY = os.environ.get("SONAR_PROJECT_KEY", "alireza")
SONAR_TOKEN_FILE = Path(os.environ.get("SONAR_TOKEN_FILE", "/run/secrets/sonar_token"))
MAX_ALERTS = 300
SCAN_TIMEOUT = 600
IMAGE_SCAN_TIMEOUT = 900
SONAR_TIMEOUT = 900

SEMGREP_IMAGE = "semgrep/semgrep:1.179.0"
CHECKOV_IMAGE = "bridgecrew/checkov:3.3.26"
TRIVY_IMAGE = "aquasec/trivy:0.75.0"
TRIVY_CACHE = "/var/lib/trivy-cache"
SONAR_IMAGE = "sonarsource/sonar-scanner-cli:12.2"

lock = threading.Lock()
scans = {}
alerts = []


def utcnow():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def load_state():
    DATA.mkdir(parents=True, exist_ok=True)
    alert_file = DATA / "alerts.json"
    if alert_file.exists():
        try:
            alerts.extend(json.loads(alert_file.read_text())[-MAX_ALERTS:])
        except json.JSONDecodeError:
            pass
    scan_dir = DATA / "scans"
    scan_dir.mkdir(parents=True, exist_ok=True)
    for path in scan_dir.glob("*.json"):
        try:
            item = json.loads(path.read_text())
        except json.JSONDecodeError:
            continue
        if item.get("status") == "running":
            item["status"] = "failed"
            item["error"] = "The console restarted during the scan."
            path.write_text(json.dumps(item, ensure_ascii=False))
        scans[item["id"]] = item


def save_scan(item):
    path = DATA / "scans" / f"{item['id']}.json"
    path.write_text(json.dumps(item, ensure_ascii=False))


def save_alerts():
    (DATA / "alerts.json").write_text(json.dumps(alerts[-MAX_ALERTS:], ensure_ascii=False))


def valid_repo(url):
    parsed = urlparse(url.strip())
    if parsed.scheme not in {"https", "http"} or not parsed.netloc:
        return False
    if ".." in parsed.path or any(ch in url for ch in "\n\r\x00"):
        return False
    return True


def docker_client():
    return docker.from_env()


def run_tool(client, image, entrypoint, command, host_path):
    client.images.pull(image)
    container = client.containers.run(
        image,
        command=command,
        entrypoint=entrypoint,
        volumes={host_path: {"bind": "/src", "mode": "ro"}},
        working_dir="/src",
        detach=True,
        remove=False,
        network_mode="bridge",
    )
    try:
        result = container.wait(timeout=SCAN_TIMEOUT)
        stdout = container.logs(stdout=True, stderr=False)
        stderr = container.logs(stdout=False, stderr=True)
        return result.get("StatusCode", 1), stdout.decode("utf-8", "replace"), stderr.decode("utf-8", "replace")
    finally:
        try:
            container.remove(force=True)
        except DockerException:
            pass


def parse_json_blob(raw):
    text = raw.strip()
    starts = [pos for pos in (text.find("{"), text.find("[")) if pos >= 0]
    if not starts:
        raise json.JSONDecodeError("no json", text, 0)
    return json.loads(text[min(starts):])


def parse_semgrep(raw):
    data = parse_json_blob(raw)
    findings = []
    for item in data.get("results", []):
        extra = item.get("extra") or {}
        findings.append(
            {
                "tool": "semgrep",
                "severity": extra.get("severity") or "INFO",
                "check": item.get("check_id") or "",
                "path": item.get("path") or "",
                "line": (item.get("start") or {}).get("line"),
                "message": extra.get("message") or "",
            }
        )
    return findings


def parse_checkov(raw):
    data = parse_json_blob(raw)
    if isinstance(data, list):
        data = data[0] if data else {}
    findings = []
    for item in data.get("results", {}).get("failed_checks", []):
        findings.append(
            {
                "tool": "checkov",
                "severity": item.get("severity") or "UNKNOWN",
                "check": item.get("check_id") or "",
                "path": item.get("file_path") or "",
                "line": item.get("file_line_range", [None])[0],
                "message": item.get("check_name") or "",
            }
        )
    return findings


def parse_trivy(raw):
    return parse_trivy_report(parse_json_blob(raw))


def _container_output(container, timeout):
    try:
        result = container.wait(timeout=timeout)
        stdout = container.logs(stdout=True, stderr=False)
        stderr = container.logs(stdout=False, stderr=True)
        code = result.get("StatusCode", 1)
        return (
            code,
            stdout.decode("utf-8", "replace"),
            stderr.decode("utf-8", "replace"),
        )
    finally:
        try:
            container.remove(force=True)
        except DockerException:
            pass


def run_trivy(client, host_path):
    client.images.pull(TRIVY_IMAGE)
    container = client.containers.run(
        TRIVY_IMAGE,
        command=[
            "fs",
            "--format",
            "json",
            "--scanners",
            "vuln,misconfig,secret",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
            "/src",
        ],
        entrypoint=["trivy"],
        volumes={
            host_path: {"bind": "/src", "mode": "ro"},
            TRIVY_CACHE: {"bind": "/cache", "mode": "rw"},
        },
        working_dir="/src",
        detach=True,
        remove=False,
        network_mode="bridge",
    )
    return _container_output(container, SCAN_TIMEOUT)


def run_trivy_image(client, image_ref):
    client.images.pull(TRIVY_IMAGE)
    container = client.containers.run(
        TRIVY_IMAGE,
        command=[
            "image",
            "--format",
            "json",
            "--scanners",
            "vuln,misconfig,secret",
            "--skip-version-check",
            "--cache-dir",
            "/cache",
            "--image-src",
            "docker,remote",
            image_ref,
        ],
        entrypoint=["trivy"],
        environment={"DOCKER_HOST": "unix:///var/run/docker.sock"},
        volumes={
            "/var/run/docker.sock": {"bind": "/var/run/docker.sock", "mode": "rw"},
            TRIVY_CACHE: {"bind": "/cache", "mode": "rw"},
        },
        detach=True,
        remove=False,
        network_mode="bridge",
    )
    return _container_output(container, IMAGE_SCAN_TIMEOUT)


def local_image_catalog():
    client = docker_client()
    raw = []
    for image in client.images.list():
        attrs = image.attrs or {}
        raw.append(
            {
                "tags": list(image.tags or []),
                "id": image.id or "",
                "size": int(attrs.get("Size") or 0),
                "created": attrs.get("Created") or "",
            }
        )
    return image_rows(raw)


def sonar_token():
    if not SONAR_TOKEN_FILE.is_file():
        raise RuntimeError("The SonarQube token is not configured.")
    token = SONAR_TOKEN_FILE.read_text().strip()
    if not token:
        raise RuntimeError("The SonarQube token is empty.")
    return token


def sonar_project_key():
    if not re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", SONAR_PROJECT_KEY):
        raise RuntimeError("The SonarQube project key is invalid.")
    return SONAR_PROJECT_KEY


def redact(text, token):
    if token and token in text:
        return text.replace(token, "***")
    return text


def sonar_api(path, params):
    token = sonar_token()
    url = SONAR_URL.rstrip("/") + path + "?" + urllib.parse.urlencode(params)
    request = urllib.request.Request(url, headers={"Authorization": "Bearer " + token})
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            return json.loads(response.read().decode())
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", "replace")[:300]
        raise RuntimeError(f"SonarQube returned {exc.code}: {detail}") from exc


def fetch_sonar_summary(key):
    gate = sonar_api("/api/qualitygates/project_status", {"projectKey": key})
    measures = sonar_api(
        "/api/measures/component",
        {"component": key, "metricKeys": "bugs,vulnerabilities,code_smells,security_hotspots"},
    )
    values = {
        item.get("metric"): item.get("value")
        for item in measures.get("component", {}).get("measures", [])
    }

    def number(metric):
        try:
            return int(values.get(metric) or 0)
        except ValueError:
            return 0

    return {
        "project_key": key,
        "quality_gate": (gate.get("projectStatus") or {}).get("status") or "",
        "bugs": number("bugs"),
        "vulnerabilities": number("vulnerabilities"),
        "code_smells": number("code_smells"),
        "security_hotspots": number("security_hotspots"),
        "url": SONAR_URL.rstrip("/") + "/dashboard?id=" + urllib.parse.quote(key),
        "error": "",
    }


def empty_sonar(key, error):
    return {
        "project_key": key,
        "quality_gate": "",
        "bugs": 0,
        "vulnerabilities": 0,
        "code_smells": 0,
        "security_hotspots": 0,
        "url": SONAR_URL.rstrip("/") + "/dashboard?id=" + urllib.parse.quote(key),
        "error": error,
    }


def run_sonar(client, host_path):
    token = sonar_token()
    key = sonar_project_key()
    client.images.pull(SONAR_IMAGE)
    container = client.containers.run(
        SONAR_IMAGE,
        command=[
            f"-Dsonar.projectKey={key}",
            "-Dsonar.sources=.",
            "-Dsonar.qualitygate.wait=true",
            "-Dsonar.qualitygate.timeout=480",
            "-Dsonar.scm.disabled=true",
        ],
        environment={
            "SONAR_HOST_URL": SONAR_URL,
            "SONAR_TOKEN": token,
            "SONAR_SCANNER_JAVA_OPTS": "-Xmx384m",
        },
        volumes={host_path: {"bind": "/usr/src", "mode": "rw"}},
        working_dir="/usr/src",
        mem_limit="896m",
        detach=True,
        remove=False,
        network_mode="bridge",
    )
    try:
        result = container.wait(timeout=SONAR_TIMEOUT)
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", "replace")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", "replace")
        code = result.get("StatusCode", 1)
    finally:
        try:
            container.remove(force=True)
        except DockerException:
            pass
    logs = redact(stdout + "\n" + stderr, token)
    uploaded = "ANALYSIS SUCCESSFUL" in logs or "QUALITY GATE STATUS" in logs
    if not uploaded:
        tail = "\n".join(logs.splitlines()[-25:])[-1500:]
        raise RuntimeError(tail or f"SonarQube finished with code {code}.")
    return fetch_sonar_summary(key)


def record_tool(findings, notes, name, parser, code, stdout, stderr):
    try:
        findings.extend(parser(stdout))
    except json.JSONDecodeError:
        notes.append(f"{name} output was not JSON:\n" + (stdout or stderr)[-1500:])
    if code not in (0, 1):
        notes.append(stderr[-1500:])


def finish_scan(item, findings, notes):
    item["findings"] = findings
    item["phase"] = ""
    sonar_error = (item.get("sonar") or {}).get("error") or ""
    if item["tools"] == ["sonar"] and sonar_error:
        item["status"] = "failed"
        item["error"] = sonar_error
    else:
        item["status"] = "done"
        item["error"] = "\n".join(note for note in notes if note)
    item["finished_at"] = utcnow()


def fail_scan(item, exc):
    item["status"] = "failed"
    item["phase"] = ""
    item["error"] = str(exc)[-2000:]
    item["finished_at"] = utcnow()


def execute_image_scan(item):
    try:
        item["phase"] = "Trivy"
        save_scan(item)
        code, stdout, stderr = run_trivy_image(docker_client(), item["image"])
        findings = []
        notes = []
        record_tool(findings, notes, "Trivy", parse_trivy, code, stdout, stderr)
        finish_scan(item, findings, notes)
    except (
        ContainerError,
        DockerException,
        ImageNotFound,
        OSError,
        RuntimeError,
        json.JSONDecodeError,
        TimeoutError,
    ) as exc:
        fail_scan(item, exc)
    finally:
        save_scan(item)


def execute_scan(scan_id):
    item = scans[scan_id]
    if item.get("target") == "image":
        execute_image_scan(item)
        return
    host_path = os.path.join(HOST_SCAN_DIR, scan_id)
    local_path = SCAN_DIR / scan_id
    try:
        local_path.parent.mkdir(parents=True, exist_ok=True)
        if local_path.exists():
            shutil.rmtree(local_path)
        clone = __import__("subprocess").run(
            ["git", "clone", "--depth", "1", item["repo"], str(local_path)],
            capture_output=True,
            text=True,
            timeout=180,
        )
        if clone.returncode != 0:
            raise RuntimeError(clone.stderr.strip() or "git clone failed")
        client = docker_client()
        findings = []
        notes = []
        if "semgrep" in item["tools"]:
            item["phase"] = "Semgrep"
            save_scan(item)
            code, stdout, stderr = run_tool(
                client,
                SEMGREP_IMAGE,
                "semgrep",
                ["scan", "--config", "auto", "--json", "."],
                host_path,
            )
            record_tool(findings, notes, "Semgrep", parse_semgrep, code, stdout, stderr)
        if "checkov" in item["tools"]:
            item["phase"] = "Checkov"
            save_scan(item)
            code, stdout, stderr = run_tool(
                client,
                CHECKOV_IMAGE,
                "checkov",
                ["-d", "/src", "-o", "json", "--quiet"],
                host_path,
            )
            record_tool(findings, notes, "Checkov", parse_checkov, code, stdout, stderr)
        if "trivy" in item["tools"]:
            item["phase"] = "Trivy"
            save_scan(item)
            code, stdout, stderr = run_trivy(client, host_path)
            record_tool(findings, notes, "Trivy", parse_trivy, code, stdout, stderr)
        if "sonar" in item["tools"]:
            item["phase"] = "SonarQube"
            save_scan(item)
            try:
                item["sonar"] = run_sonar(client, host_path)
            except Exception as exc:
                key = SONAR_PROJECT_KEY if re.fullmatch(r"[A-Za-z0-9_.:-]{1,200}", SONAR_PROJECT_KEY) else "alireza"
                item["sonar"] = empty_sonar(key, str(exc)[-1500:])
        finish_scan(item, findings, notes)
    except (ContainerError, DockerException, ImageNotFound, OSError, RuntimeError, json.JSONDecodeError, TimeoutError) as exc:
        fail_scan(item, exc)
    finally:
        save_scan(item)
        if local_path.exists():
            shutil.rmtree(local_path, ignore_errors=True)


@app.get("/")
@app.get("/login")
def index():
    return render_template("index.html", sonar_url=SONAR_URL)


@app.post("/api/scans")
def create_scan():
    user = getattr(g, "user", None)
    if not isinstance(user, dict):
        return jsonify({"error": "You do not have permission."}), 403
    body = request.get_json(silent=True) or {}
    target = body.get("target") or "repo"
    if target not in {"repo", "image"}:
        return jsonify({"error": "Invalid scan type."}), 400
    tools = [
        tool
        for tool in body.get("tools") or []
        if tool in {"semgrep", "checkov", "sonar", "trivy"}
    ]
    image = ""
    repo = ""
    if target == "image":
        image = (body.get("image") or "").strip()
        if not valid_image_ref(image):
            return jsonify({"error": "Image name is invalid. Use a name like nginx:1.27."}), 400
        if tools != ["trivy"]:
            return jsonify({"error": "Image scans run with Trivy only."}), 400
    else:
        repo = (body.get("repo") or "").strip()
        if not valid_repo(repo):
            return jsonify({"error": "Repository URL must start with http or https."}), 400
        if not tools:
            return jsonify({"error": "Select at least one tool."}), 400
    if not can_start_scan(user, tools):
        return jsonify({"error": "You do not have permission."}), 403
    with lock:
        if any(item["status"] == "running" for item in scans.values()):
            return jsonify({"error": "A scan is already running."}), 409
        scan_id = uuid.uuid4().hex[:12]
        item = {
            "id": scan_id,
            "target": target,
            "repo": repo,
            "image": image,
            "tools": tools,
            "status": "running",
            "findings": [],
            "sonar": None,
            "phase": "Trivy" if target == "image" else "clone",
            "error": "",
            "created_at": utcnow(),
            "finished_at": "",
            "owner": user.get("username") or "",
        }
        scans[scan_id] = item
        save_scan(item)
    threading.Thread(target=execute_scan, args=(scan_id,), daemon=True).start()
    return jsonify(item), 202


@app.get("/api/images")
def get_images():
    user = getattr(g, "user", None) or {}
    if not can_start_scan(user, ["trivy"]):
        return jsonify({"error": "You do not have permission."}), 403
    try:
        return jsonify(local_image_catalog())
    except (DockerException, OSError, TypeError, ValueError) as exc:
        app.logger.error("image list failed: %s", type(exc).__name__)
        return jsonify({"error": "Could not list local images."}), 503


@app.get("/api/scans")
def list_scans():
    user = getattr(g, "user", None) or {}
    summary = request.args.get("summary") == "1"
    ordered = sorted(scans.values(), key=lambda item: item["created_at"], reverse=True)
    visible = []
    for item in ordered:
        shown = present_scan(user, item, summary=summary)
        if shown is not None:
            visible.append(shown)
    return jsonify(visible[:20])


@app.get("/api/scans/<scan_id>")
def get_scan(scan_id):
    user = getattr(g, "user", None) or {}
    item = scans.get(scan_id)
    if not item:
        return jsonify({"error": "Not found"}), 404
    shown = present_scan(user, item, summary=False)
    if shown is None:
        return jsonify({"error": "Not found"}), 404
    return jsonify(shown)


@app.post("/api/falco")
def ingest_falco():
    payload = request.get_json(silent=True)
    if payload is None:
        raw = request.get_data(as_text=True).strip()
        try:
            payload = json.loads(raw) if raw else {}
        except json.JSONDecodeError:
            payload = {"output": raw}
    alert = {
        "time": payload.get("time") or utcnow(),
        "priority": payload.get("priority") or "Notice",
        "rule": payload.get("rule") or "",
        "output": payload.get("output") or "",
        "source": (payload.get("hostname") or payload.get("output_fields", {}).get("host.name") or ""),
    }
    with lock:
        alerts.append(alert)
        del alerts[:-MAX_ALERTS]
        save_alerts()
    return jsonify({"ok": True})


@app.get("/api/falco")
def list_falco():
    return jsonify(list(reversed(alerts[-100:])))


install_auth(app)


def boot():
    """Load saved scans, then refuse to serve until login storage is ready."""

    load_state()
    try:
        prepare_auth()
    except Exception as exc:
        print(f"auth startup failed: {type(exc).__name__}", file=sys.stderr)
        raise SystemExit(1) from None


if os.environ.get("CONSOLE_SKIP_BOOT") != "1":
    boot()

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8080, threaded=True)
