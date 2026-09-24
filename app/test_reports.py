import asyncio
import json
import types

from app import reports
from app.reports import Reporter, ThreadLink, _project_link, _reporter, _load_pmc_report, load_pmc_report, load_pmc_reports


def _write_report(path, label, *, subj="[SECURITY] a flaw"):
    path = path.parent / f"{label}.json"
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
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    path = _write_report(tmp_path, "2024-03-01 native a flaw wf untriaged")
    report = load_pmc_report("commons", path)
    assert report.subproject == "native"


def test_subproject_after_single_cve(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    path = _write_report(tmp_path, "CVE-2024-1234 lang a flaw")
    report = load_pmc_report("commons", path)
    assert report.subproject == "lang"


def test_subproject_after_multiple_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    path = _write_report(tmp_path, "CVE-2024-1234 CVE-2024-5678 io a flaw")
    report = load_pmc_report("commons", path)
    assert report.subproject == "io"


def test_subproject_none_when_no_prefix(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    path = _write_report(tmp_path, "single")
    report = load_pmc_report("commons", path)
    assert report.subproject is None


def _full_config(tmp_path, pmcs_in_attic=()):
    return types.SimpleNamespace(
        data_dir_path=tmp_path,
        pmcs_in_attic=list(pmcs_in_attic),
        pmcs_using_jira={},
        pmcs_using_github={},
        pmcs_with_failing_moderation=[],
    )


def test_security_pmc_includes_attic_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path, pmcs_in_attic=["hivemind"])
    )
    (tmp_path / "security").mkdir()
    (tmp_path / "hivemind").mkdir()
    _write_report(tmp_path / "security" / "x", "own report")
    _write_report(tmp_path / "hivemind" / "x", "attic report")

    result = asyncio.run(load_pmc_reports("security"))

    assert {r.security_team_name for r in result} == {"own report", "attic report"}
    by_name = {r.security_team_name: r for r in result}
    assert by_name["attic report"].subproject == "hivemind"
    assert by_name["own report"].subproject is None


def test_ordinary_pmc_does_not_include_attic_reports(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path, pmcs_in_attic=["hivemind"])
    )
    (tmp_path / "cassandra").mkdir()
    (tmp_path / "hivemind").mkdir()
    _write_report(tmp_path / "cassandra" / "x", "own report")
    _write_report(tmp_path / "hivemind" / "x", "attic report")

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert {r.security_team_name for r in result} == {"own report"}


def test_security_pmc_tolerates_missing_and_invalid_attic_dirs(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config,
        "get",
        lambda: _full_config(tmp_path, pmcs_in_attic=["hivemind", "../escape"]),
    )
    (tmp_path / "security").mkdir()
    _write_report(tmp_path / "security" / "x", "own report")

    result = asyncio.run(load_pmc_reports("security"))

    assert {r.security_team_name for r in result} == {"own report"}


def test_asf_member_link_non_apache_to_uses_security_apache_org(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    email = {
        'subj': 'reporting a vuln',
        'to': 'Disclosure <disclosure@aisle.com>',
        'message_id': '<7200416e-bd53-4026-a0a1-f3cf4c00de86n@aisle.com>',
        'mailtime': 1700000000,
    }
    assert _asf_member_link("cassandra", email) == (
        'https://lists.apache.org/thread/'
        '<7200416e-bd53-4026-a0a1-f3cf4c00de86n%40aisle.com>'
        '?<security.apache.org>'
    )

def _asf_member_link(pmc, email):
    return _load_pmc_report(pmc, "2026-09-09 foo", [], [ email ]).asf_member_link

def test_asf_member_link_apache_to_uses_to_domain(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path, pmcs_in_attic=["hivemind"])
    )
    email = {
        'subj': 'reporting a vuln',
        'to': 'security@cassandra.apache.org',
        'message_id': '<abc123@cassandra.apache.org>',
        'mailtime': 1700000000,
    }
    assert _asf_member_link("cassandra", email) == (
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


def test_asf_member_link_uses_cc_when_to_is_non_apache(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    email = {
        'subj': 'reporting a vuln',
        'to': 'reporter@aisle.com',
        'cc': 'security@cassandra.apache.org',
        'message_id': '<abc@aisle.com>',
        'mailtime': 1700000000,
    }
    assert _asf_member_link("cassandra", email) == (
        'https://lists.apache.org/thread/'
        '<abc%40aisle.com>'
        '?<security.cassandra.apache.org>'
    )


def test_asf_member_link_prefers_to_over_cc(tmp_path, monkeypatch):
    monkeypatch.setattr(
        reports.config, "get", lambda: _full_config(tmp_path)
    )
    email = {
        'subj': 'reporting a vuln',
        'to': 'security@cassandra.apache.org',
        'cc': 'security@kafka.apache.org',
        'message_id': '<abc@cassandra.apache.org>',
        'mailtime': 1700000000,
    }
    assert _asf_member_link("cassandra", email) == (
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


def _email(subj, message_id):
    return {
        'subj': subj,
        'from': 'Jane Reporter <jane@aisle.com>',
        'to': 'security@cassandra.apache.org',
        'message_id': message_id,
        'mailtime': 1700000000,
    }


def test_replies_are_not_reported_as_duplicates(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    report = _load_pmc_report("cassandra", "2026-09-09 foo", [], [
        _email("[SECURITY] a flaw", "<a@aisle.com>"),
        _email("Re: [SECURITY] a flaw", "<b@cassandra.apache.org>"),
        _email("RE: Re:  a   FLAW", "<c@cassandra.apache.org>"),
    ])
    assert report.duplicates == ()


def test_distinct_threads_in_one_report_are_all_linked(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    report = _load_pmc_report("cassandra", "2026-09-09 foo", [], [
        _email("[SECURITY] SQL injection in search", "<a@aisle.com>"),
        _email("Possible SQLi found in /search", "<b@example.net>"),
        _email("Re: Possible SQLi found in /search", "<c@cassandra.apache.org>"),
        _email("Third report", "<d@example.org>"),
    ])
    assert report.title == "SQL injection in search"
    assert report.link == 'https://lists.apache.org/thread/<a%40aisle.com>?<security.cassandra.apache.org>'
    assert report.duplicates == (
        ThreadLink("Possible SQLi found in /search",
                   'https://lists.apache.org/thread/<b%40example.net>?<security.cassandra.apache.org>'),
        ThreadLink("Third report",
                   'https://lists.apache.org/thread/<d%40example.org>?<security.cassandra.apache.org>'),
    )
def _write_label(pmc_dir, label, emails):
    pmc_dir.mkdir(parents=True, exist_ok=True)
    path = pmc_dir / label
    path.write_text(json.dumps([
        {
            "from": "Security Team <security@apache.org>",
            "to": "security@cassandra.apache.org",
            **email,
        }
        for email in emails
    ]))
    return path


def test_glasswing_lists_only_unpublished_cves(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-glasswing.json", [
        {"subj": "CVE-2026-1111 allocated for XSS in the web console",
         "message_id": "<alloc1@apache.org>", "mailtime": 1700000000},
        {"subj": "CVE-2026-2222 allocated for path traversal",
         "message_id": "<alloc2@apache.org>", "mailtime": 1700001000},
        {"subj": "CVE-2026-1111 was pushed to cve.org",
         "message_id": "<pushed1@apache.org>", "mailtime": 1700002000},
    ])

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert [r.cves for r in result] == [["CVE-2026-2222"]]
    assert result[0].state == reports.GLASSWING_STATE
    assert result[0].title == "CVE-2026-2222 allocated for path traversal"
    assert result[0].message_id == "<alloc2@apache.org>"
    assert result[0].date.isoformat() == "2023-11-14"


def test_glasswing_keeps_the_allocating_mail_of_a_cve_mentioned_twice(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-glasswing.json", [
        {"subj": "CVE-2026-1111 allocated for XSS in the web console",
         "message_id": "<alloc@apache.org>", "mailtime": 1700000000},
        {"subj": "Re: CVE-2026-1111 allocated for XSS in the web console",
         "message_id": "<reply@apache.org>", "mailtime": 1700003000},
    ])

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert [r.message_id for r in result] == ["<alloc@apache.org>"]


def test_glasswing_ignores_mails_without_a_cve(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-glasswing.json", [
        {"subj": "audit kickoff", "message_id": "<kick@apache.org>", "mailtime": 1700000000},
    ])

    assert asyncio.run(load_pmc_reports("cassandra")) == []


def test_not_forwarded_lists_one_report_per_thread_head(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-non-fwd.json", [
        {"subj": "Re: a flaw in your project",
         "message_id": "<reply-a@aisle.com>", "mailtime": 1700002000},
        {"subj": "a flaw in your project",
         "message_id": "<head-a@aisle.com>", "mailtime": 1700000000},
        {"subj": "[SECURITY] another finding",
         "message_id": "<head-b@aisle.com>", "mailtime": 1700001000},
        {"subj": "Re: [SECURITY] another finding",
         "message_id": "<reply-b@aisle.com>", "mailtime": 1700003000},
    ])

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert {r.message_id for r in result} == {"<head-a@aisle.com>", "<head-b@aisle.com>"}
    assert {r.state for r in result} == {reports.NOT_FORWARDED_STATE}
    assert {r.title for r in result} == {"a flaw in your project", "another finding"}
    assert all(r.cves == [] for r in result)


def test_not_forwarded_reports_keep_the_reporter(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-non-fwd.json", [
        {"subj": "a flaw in your project",
         "from": "Jane Reporter <jane@aisle.com>",
         "to": "security@apache.org",
         "message_id": "<head@aisle.com>", "mailtime": 1700000000},
    ])

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert result[0].reporter == Reporter(name="Jane Reporter", email="jane@aisle.com")


def test_special_labels_are_not_loaded_as_a_single_report(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-glasswing.json", [
        {"subj": "audit kickoff", "message_id": "<kick@apache.org>", "mailtime": 1700000000},
    ])
    _write_report(tmp_path / "cassandra" / "x", "2024-03-01 a flaw wf untriaged.json")

    result = asyncio.run(load_pmc_reports("cassandra"))

    assert [r.security_team_name for r in result] == ["2024-03-01 a flaw wf untriaged.json"]


def test_label_with_unusable_mails_is_skipped(tmp_path, monkeypatch):
    monkeypatch.setattr(reports.config, "get", lambda: _full_config(tmp_path))
    _write_label(tmp_path / "cassandra", "aaa-non-fwd.json", [
        {"subj": "no message id here", "mailtime": 1700000000},
    ])

    assert asyncio.run(load_pmc_reports("cassandra")) == []
