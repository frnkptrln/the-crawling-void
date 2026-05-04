import json
import subprocess
from pathlib import Path


def run(cmd):
    subprocess.run(cmd, check=True, env={**__import__("os").environ, "PYTHONPATH": "."})


def test_tox_hunter(tmp_path):
    out = tmp_path / "o.json"
    md = tmp_path / "o.md"
    run(["python", "tools/tox_hunter.py", "tests/fixtures/sample.html", "--output", str(out), "--markdown", str(md)])
    data = json.loads(out.read_text())
    assert "analyst@example.org" in data["email"]
    assert any(x.endswith(".onion") for x in data["onion"])


def test_phantom_diff(tmp_path):
    a = tmp_path / "a.json"
    b = tmp_path / "b.json"
    a.write_text(json.dumps({"urls": ["a", "b"]}))
    b.write_text(json.dumps({"urls": ["b", "c"]}))
    out = tmp_path / "d.json"
    run(["python", "tools/phantom_diff.py", str(a), str(b), "--output", str(out)])
    diff = json.loads(out.read_text())
    assert "c" in diff["added"]


def test_abyssal_mapper_html(tmp_path):
    out = tmp_path / "g.json"
    gml = tmp_path / "g.graphml"
    run(["python", "tools/abyssal_mapper.py", "--html", "tests/fixtures/sample.html", "--output", str(out), "--graphml", str(gml)])
    data = json.loads(out.read_text())
    assert "http://example.com/a" in data["nodes"]
