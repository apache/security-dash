import asyncio
import json
import types

from app import reports
from app.reports import Reporter, _asf_member_link, _project_link, _reporter, load_pmc_report, load_pmc_reports


def _write_report(path, label, *, subj="[SECURITY] a flaw"):
    path = path.parent / label
    path.write_text(json.dumps([
        {
            "subj": subj,
            "from": "Jane Reporter <jane@aisle.com>",
            "to": "security@cassandra.apache.org",
            "message_id": "<abc@cassandra.apache.org>",
            "mailtime": 1700000000,
        }
    ]))
    return path


def test_subproject_after_leading_date(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: types.SimpleNamespace(pmcs_using_jira={})
    )
    path = _write_report(tmp_path, "2024-03-01 native a flaw wf untriaged.json")
    report = load_pmc_report("commons", path)
    assert report.subproject == "native"


def test_subproject_after_single_cve(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: types.SimpleNamespace(pmcs_using_jira={})
    )
    path = _write_report(tmp_path, "CVE-2024-1234 lang a flaw.json")
    report = load_pmc_report("commons", path)
    assert report.subproject == "lang"


def test_subproject_after_multiple_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: types.SimpleNamespace(pmcs_using_jira={})
    )
    path = _write_report(tmp_path, "CVE-2024-1234 CVE-2024-5678 io a flaw.json")
    report = load_pmc_report("commons", path)
    assert report.subproject == "io"


def test_subproject_none_when_no_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: types.SimpleNamespace(pmcs_using_jira={})
    )
    path = _write_report(tmp_path, "single.json")
    report = load_pmc_report("commons", path)
    assert report.subproject is None


def _full_config(tmp_path, attic_pmcs=()):
    return types.SimpleNamespace(
        data_dir_path=tmp_path,
        attic_pmcs=list(attic_pmcs),
        pmcs_using_jira={},
        pmcs_using_github={},
    )


def test_security_pmc_includes_attic_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path, attic_pmcs=["hivemind"])
    )
    (tmp_path / "security").mkdir()
    (tmp_path / "hivemind").mkdir()
    _write_report(tmp_path / "security" / "x", "own report.json")
    _write_report(tmp_path / "hivemind" / "x", "attic report.json")

    result = asyncio.run(load_pmc_reports("security"))

    assert {r.security_team_name for r in result} == {"own report.json", "attic report.json"}
    by_name = {r.security_team_name: r for r in result}
    assert by_name["attic report.json"].subproject == "hivemind"
    assert by_name["own report.json"].subproject is None


def test_ordinary_pmc_does_not_include_attic_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path, attic_pmcs=["hivemind"])
    )
    (tmp_path / "cassandra").mkdir()
    (tmp_path / "hivemind").mkdir()
    _write_report(tmp_path / "cassandra" / "x", "own report.json")
    _write_report(tmp_path / "hivemind" / "x", "attic report.json")

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert {r.security_team_name for r in result} == {"own report.json"}


def test_security_pmc_tolerates_missing_and_invalid_attic_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config,
        "get",
        lambda: _full_config(tmp_path, attic_pmcs=["hivemind", "../escape"]),
    )
    (tmp_path / "security").mkdir()
    _write_report(tmp_path / "security" / "x", "own report.json")

    result = asyncio.run(load_pmc_reports("security"))

    assert {r.security_team_name for r in result} == {"own report.json"}


def test_asf_member_link_non_apache_to_uses_security_apache_org():
    email = {
        'to': 'Disclosure <disclosure@aisle.com>',
        'message_id': '<7200416e-bd53-4026-a0a1-f3cf4c00de86n@aisle.com>',
    }
    assert _asf_member_link(email) == (
        'https://lists.apache.org/thread/'
        '<7200416e-bd53-4026-a0a1-f3cf4c00de86n%40aisle.com>'
        '?<security.apache.org>'
    )


def test_asf_member_link_apache_to_uses_to_domain():
    email = {
        'to': 'security@cassandra.apache.org',
        'message_id': '<abc123@cassandra.apache.org>',
    }
    assert _asf_member_link(email) == (
        'https://lists.apache.org/thread/'
        '<abc123%40cassandra.apache.org>'
        '?<security.cassandra.apache.org>'
    )


def test_project_link_returns_first_apache_email():
    emails = [
        {'to': 'reporter@aisle.com', 'message_id': '<a@aisle.com>'},
        {'to': 'security@cassandra.apache.org', 'message_id': '<b@cassandra.apache.org>'},
        {'to': 'security@cassandra.apache.org', 'message_id': '<c@cassandra.apache.org>'},
    ]
    assert _project_link(emails) == (
        'https://lists.apache.org/thread/'
        '<b%40cassandra.apache.org>'
        '?<security.cassandra.apache.org>'
    )


def test_project_link_only_considers_first_five():
    emails = [{'to': 'reporter@aisle.com', 'message_id': f'<{i}@aisle.com>'} for i in range(5)]
    emails.append({'to': 'security@cassandra.apache.org', 'message_id': '<late@cassandra.apache.org>'})
    assert _project_link(emails) is None


def test_project_link_returns_none_when_no_apache_recipient():
    emails = [
        {'to': 'reporter@aisle.com', 'message_id': '<a@aisle.com>'},
        {'to': 'disclosure@vendor.example', 'message_id': '<b@vendor.example>'},
    ]
    assert _project_link(emails) is None


def test_asf_member_link_uses_cc_when_to_is_non_apache():
    email = {
        'to': 'reporter@aisle.com',
        'cc': 'security@cassandra.apache.org',
        'message_id': '<abc@aisle.com>',
    }
    assert _asf_member_link(email) == (
        'https://lists.apache.org/thread/'
        '<abc%40aisle.com>'
        '?<security.cassandra.apache.org>'
    )


def test_asf_member_link_prefers_to_over_cc():
    email = {
        'to': 'security@cassandra.apache.org',
        'cc': 'security@kafka.apache.org',
        'message_id': '<abc@cassandra.apache.org>',
    }
    assert _asf_member_link(email) == (
        'https://lists.apache.org/thread/'
        '<abc%40cassandra.apache.org>'
        '?<security.cassandra.apache.org>'
    )


def test_project_link_finds_apache_address_in_cc():
    emails = [
        {
            'to': 'reporter@aisle.com',
            'cc': 'security@cassandra.apache.org',
            'message_id': '<a@aisle.com>',
        },
    ]
    assert _project_link(emails) == (
        'https://lists.apache.org/thread/'
        '<a%40aisle.com>'
        '?<security.cassandra.apache.org>'
    )


def test_reporter_uses_from_when_not_via():
    email = {'from': 'Jane Q. Reporter <jane@aisle.com>'}
    assert _reporter(email) == Reporter(name='Jane Q. Reporter', email='jane@aisle.com')


def test_reporter_falls_back_to_reply_to_when_via_security_list():
    email = {
        'from': '\"Jane Reporter via Security\" <security@apache.org>',
        'reply_to': 'Jane Reporter <jane@aisle.com>',
    }
    assert _reporter(email) == Reporter(name='Jane Reporter', email='jane@aisle.com')


def test_reporter_falls_back_to_reply_to_when_via_project_list():
    email = {
        'from': 'Jane Reporter via Security <security@cassandra.apache.org>',
        'reply_to': 'Jane Reporter <jane@aisle.com>',
    }
    assert _reporter(email) == Reporter(name='Jane Reporter', email='jane@aisle.com')


def test_reporter_returns_none_when_via_apache_and_no_reply_to():
    email = {'from': 'Jane Reporter via Security <security@cassandra.apache.org>'}
    assert _reporter(email) is None


def test_reporter_returns_none_when_from_missing():
    assert _reporter({}) is None


def test_reporter_initials_from_name():
    assert Reporter(name='Jane Q. Reporter', email='jane@aisle.com').initials == 'JQR'


def test_reporter_initials_fall_back_to_email_local_part():
    assert Reporter(name='', email='alice@example.com').initials == 'A'
