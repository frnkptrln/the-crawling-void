from crawlers import api_crawler, dumb_crawler, intel_harvester, spa_path_crawler


def test_spa_links_are_same_origin_and_tokens_are_removed():
    root = "http://alphaexamplealpha.onion/?path=/"
    html = """
    <a href="/?path=/Reports&token=secret">reports</a>
    <a href="http://otherexample.onion/?path=/Elsewhere">other</a>
    """
    links = spa_path_crawler.extract_path_links(html, root, root, "token")
    assert links == ["http://alphaexamplealpha.onion/?path=%2FReports"]
    assert "secret" not in links[0]


def test_spa_generated_curl_uses_environment_placeholder():
    command = spa_path_crawler.build_curl_command(
        "http://alphaexamplealpha.onion/?path=%2Freport.zip",
        "report.zip",
        True,
        "both",
        "socks5h://localhost:9050",
        "token",
    )
    assert "${TCV_JWT_TOKEN}" in command
    assert "Bearer ${TCV_JWT_TOKEN}" in command


def test_api_query_helpers_remove_live_tokens():
    url = "http://alphaexamplealpha.onion/api?view=list&token=secret"
    clean = api_crawler.normalized_endpoint(url, "token")
    assert clean == "http://alphaexamplealpha.onion/api?view=list"
    assert "secret" not in clean


def test_api_extracts_directory_and_file_records():
    patterns = api_crawler.compile_patterns([(1, "payroll")], "literal")
    options = {
        "dir_keys": ["directories"],
        "file_keys": ["files"],
        "name_keys": ["name"],
        "path_keys": ["path"],
        "type_key": "type",
        "directory_types": {"directory"},
        "file_types": {"file"},
    }
    data = {
        "directories": [{"name": "Finance", "path": "/Finance"}],
        "files": [{"name": "payroll.xlsx", "path": "/Finance/payroll.xlsx"}],
    }
    directories, files = api_crawler.extract_api_records(data, "/", patterns, options)
    assert [record["path"] for record in directories] == ["/Finance"]
    assert any(record["path"] == "/Finance/payroll.xlsx" for record in files)


def test_open_directory_parser_stays_on_origin():
    html = """
    <h1>Index of /files/</h1>
    <a href="../">Parent Directory</a>
    <a href="reports/">reports/</a>
    <a href="report.zip">report.zip</a>
    <a href="https://other.test/leak.zip">external</a>
    """
    directories, files, reason = dumb_crawler.parse_index_links(
        html,
        "https://example.test/files/",
        "https://example.test/files/",
        True,
    )
    assert reason == ""
    assert [item["url"] for item in directories] == ["https://example.test/files/reports/"]
    assert [item["url"] for item in files] == ["https://example.test/files/report.zip"]


def test_intel_harvester_extracts_and_deduplicates_actor_indicators():
    findings = []
    seen = set()
    text = "Contact analyst@example.org or analyst [at] example [dot] org."
    intel_harvester.harvest_indicators(text, "https://example.test/post", 40, 2000, findings, seen)
    emails = [item for item in findings if item["type"] == "email"]
    assert len(emails) == 1
    assert emails[0]["normalized"] == "analyst@example.org"
