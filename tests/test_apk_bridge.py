"""APK bridge tests — app/apk.py router (NEW, hack/n3yx-scan-quality).

Uses a temp SCAN_TOOLKIT data_dir + stubbed background scan so no
apktool/jadx/semgrep/MobSF is needed. Verifies: reject non-APK,
accept .apk upload, list + detail round-trip.
"""

from __future__ import annotations


def _client(tmp_path, monkeypatch):
    from scan_toolkit.config import get_settings

    s = get_settings()
    orig_dir, orig_url = s.data_dir, s.db_url
    s.data_dir = tmp_path / "tkdata"
    s.db_url = f"sqlite+pysqlite:///{(s.data_dir / 'toolkit.db').as_posix()}"
    monkeypatch.setattr("app.apk._run_static_background", lambda eng_id: None)
    from fastapi.testclient import TestClient

    import app.main as main

    return TestClient(main.app), orig_dir, orig_url, s


def test_reject_non_apk(tmp_path, monkeypatch):
    client, orig_dir, orig_url, s = _client(tmp_path, monkeypatch)
    try:
        r = client.post(
            "/api/apk/scans",
            files={"file": ("evil.exe", b"MZ", "application/octet-stream")},
            data={"client_name": "acme", "platform": "android"},
        )
        assert r.status_code == 400
    finally:
        s.data_dir, s.db_url = orig_dir, orig_url


def test_upload_list_detail(tmp_path, monkeypatch):
    client, orig_dir, orig_url, s = _client(tmp_path, monkeypatch)
    try:
        r = client.post(
            "/api/apk/scans",
            files={"file": ("app.apk", b"PK\x03\x04fake-apk", "application/vnd.android.package-archive")},
            data={"client_name": "acme", "platform": "android", "app_version": "1.0"},
        )
        assert r.status_code == 200, r.text
        job_id = r.json()["id"]

        r2 = client.get("/api/apk/scans")
        assert r2.status_code == 200
        assert any(j["id"] == job_id for j in r2.json())

        r3 = client.get(f"/api/apk/scans/{job_id}")
        assert r3.status_code == 200
        body = r3.json()
        assert body["id"] == job_id
        assert body["binary_filename"] == "app.apk"
    finally:
        s.data_dir, s.db_url = orig_dir, orig_url
        from scan_toolkit.config import get_settings

        get_settings.cache_clear()
