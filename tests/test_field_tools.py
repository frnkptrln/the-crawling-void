import json
import subprocess
import xml.etree.ElementTree as ET

import pytest

from tools.abyssal_mapper import export_graphml
from tools.phantom_diff import compare_snapshots
from tools.shadow_fetch import candidate_status, download_candidate


def run(cmd):
    subprocess.run(cmd, check=True, env={**__import__("os").environ, "PYTHONPATH": "."})


def test_tox_hunter(tmp_path):
    out = tmp_path / "o.json"
    md = tmp_path / "o.md"
    run(["python", "tools/tox_hunter.py", "tests/fixtures/sample.html", "--output", str(out), "--markdown", str(md)])
    data = json.loads(out.read_text())
    assert "analyst@example.org" in data["email"]
    assert any(value.endswith(".onion") for value in data["onion"])


def test_phantom_diff(tmp_path):
    old = tmp_path / "old.json"
    new = tmp_path / "new.json"
    old.write_text(json.dumps({"urls": ["a", "b"]}))
    new.write_text(json.dumps({"urls": ["b", "c"]}))
    output = tmp_path / "diff.json"
    run(["python", "tools/phantom_diff.py", str(old), str(new), "--output", str(output)])
    diff = json.loads(output.read_text())
    assert diff["added"] == ["c"]
    assert diff["removed"] == ["a"]
    assert diff["changed"] == []
    assert diff["unchanged"] == ["b"]


def test_phantom_diff_detects_changes_by_stable_identity():
    old = {"files": [{"url": "https://example.test/a", "size": 10}]}
    new = {"files": [{"url": "https://example.test/a", "size": 20}]}
    diff = compare_snapshots(old, new)
    assert len(diff["changed"]) == 1
    assert diff["changed"][0]["before"]["size"] == 10
    assert diff["changed"][0]["after"]["size"] == 20


def test_phantom_diff_rejects_duplicate_identities():
    snapshot = {"files": [{"url": "https://example.test/a"}, {"url": "https://example.test/a"}]}
    with pytest.raises(ValueError, match="duplicate record identity"):
        compare_snapshots(snapshot, snapshot)


def test_abyssal_mapper_html(tmp_path):
    output = tmp_path / "graph.json"
    graphml = tmp_path / "graph.graphml"
    run(["python", "tools/abyssal_mapper.py", "--html", "tests/fixtures/sample.html", "--output", str(output), "--graphml", str(graphml)])
    data = json.loads(output.read_text())
    assert "http://example.com/a" in data["nodes"]


def test_graphml_escapes_urls_and_uses_safe_node_ids(tmp_path):
    graphml = tmp_path / "graph.graphml"
    source = "https://example.test/?a=1&b=2"
    target = "https://example.test/quoted?value=%22x%22"
    export_graphml(graphml, [source, target], [(source, target)])
    tree = ET.parse(graphml)
    namespace = {"g": "http://graphml.graphdrawing.org/xmlns"}
    labels = [node.text for node in tree.findall(".//g:data", namespace)]
    assert labels == [source, target]


def test_shadow_fetch_requires_scope_and_blocks_executables():
    hosts = {"example.test"}
    assert candidate_status("https://example.test/file.zip", hosts, {".exe"}) == "eligible"
    assert candidate_status("https://other.test/file.zip", hosts, {".exe"}) == "blocked_host"
    assert candidate_status("https://example.test/file.exe", hosts, {".exe"}) == "blocked_ext"
    assert candidate_status("file:///tmp/file.zip", hosts, {".exe"}) == "blocked_scheme"


class FakeResponse:
    def __init__(self, chunks, url="https://example.test/file.bin", headers=None):
        self._chunks = chunks
        self.url = url
        self.headers = headers or {"Content-Type": "application/octet-stream"}
        self.closed = False
        self.is_redirect = False

    def raise_for_status(self):
        return None

    def iter_content(self, chunk_size):
        yield from self._chunks

    def close(self):
        self.closed = True


class FakeSession:
    def __init__(self, response):
        self.response = response

    def get(self, *args, **kwargs):
        assert kwargs["stream"] is True
        return self.response


def test_shadow_fetch_enforces_streaming_budget(tmp_path):
    response = FakeResponse([b"1234", b"5678"])
    result = download_candidate(FakeSession(response), response.url, tmp_path, 6)
    assert result["status"] == "max_mb_exceeded"
    assert list(tmp_path.iterdir()) == []
    assert response.closed


def test_shadow_fetch_hashes_bounded_download(tmp_path):
    response = FakeResponse([b"abc", b"def"])
    result = download_candidate(FakeSession(response), response.url, tmp_path, 6)
    assert result["status"] == "downloaded"
    assert result["size"] == 6
    assert (tmp_path / result["sha256"]).read_bytes() == b"abcdef"


def test_shadow_fetch_rejects_off_scope_redirect_before_following_it(tmp_path):
    redirect = FakeResponse(
        [],
        url="https://example.test/start",
        headers={"Location": "https://other.test/file.bin"},
    )
    redirect.is_redirect = True

    class RedirectSession:
        calls = []

        def get(self, url, **kwargs):
            self.calls.append(url)
            return redirect

    session = RedirectSession()
    result = download_candidate(
        session,
        "https://example.test/start",
        tmp_path,
        100,
        {"example.test"},
        set(),
        False,
    )
    assert result["status"] == "redirect_blocked_host"
    assert session.calls == ["https://example.test/start"]
    assert redirect.closed
