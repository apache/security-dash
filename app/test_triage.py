# Licensed to the Apache Software Foundation (ASF) under one
# or more contributor license agreements.  See the NOTICE file
# distributed with this work for additional information
# regarding copyright ownership.  The ASF licenses this file
# to you under the Apache License, Version 2.0 (the
# "License"); you may not use this file except in compliance
# with the License.  You may obtain a copy of the License at
#
#   http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
# KIND, either express or implied.  See the License for the
# specific language governing permissions and limitations
# under the License.

import asyncio
import dataclasses
import datetime
import pytest
import types

from app import triage
from app.reports import Report, Reporter
from app.triage import TriageAction, TriageError, TriageUnavailable, parse_decision


def _report(message_id="<abc@cassandra.apache.org>", state="untriaged"):
    return Report(
        security_team_name="2024-03-01 a flaw",
        cves=[],
        github=None,
        jira=None,
        title="a flaw",
        message_id=message_id,
        listid="security.cassandra.apache.org",
        link="https://lists.apache.org/thread/x",
        reporter=None,
        state=state,
        subproject=None,
        timestamp=datetime.datetime(2024, 3, 1, tzinfo=datetime.timezone.utc),
    )


def _config(monkeypatch, **overrides):
    """Config with triage on for cassandra, unless a test says otherwise."""
    settings = {"pmcs_with_triage": ["cassandra"], "pmcs_with_security_emails": []}
    settings.update(overrides)
    monkeypatch.setattr(triage.config, "get", lambda: types.SimpleNamespace(**settings))


@pytest.fixture(autouse=True)
def _triage_enabled(monkeypatch):
    """Triage is on for cassandra, and no project has a security list of its own."""
    _config(monkeypatch)


def _decide(payload, candidates=None, uid="jdoe", name="John Doe"):
    candidates = [_report()] if candidates is None else candidates
    return parse_decision("cassandra", candidates, payload, uid=uid, name=name)


def test_accept_carries_feedback_and_actor():
    decision = _decide({
        "message_id": "<abc@cassandra.apache.org>",
        "action": "accept",
        "feedback": "  Thanks, we agree this is a vulnerability.  ",
        "tag": "2024-03-01 a flaw",
    })
    assert decision.action is TriageAction.ACCEPT
    assert decision.feedback == "Thanks, we agree this is a vulnerability."
    assert decision.uid == "jdoe"
    assert decision.project == "cassandra"
    assert decision.report.message_id == "<abc@cassandra.apache.org>"


def test_reject_is_allowed_for_untriaged():
    assert _decide({"message_id": "<abc@cassandra.apache.org>", "action": "reject", "tag": "2024-03-01 a flaw"}).action is TriageAction.REJECT


def test_feedback_is_optional():
    assert _decide({"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"}).feedback == ""


def test_unknown_action_is_rejected():
    with pytest.raises(TriageError) as e:
        _decide({"message_id": "<abc@cassandra.apache.org>", "action": "delete"})
    assert e.value.status == 400


def test_missing_action_is_rejected():
    with pytest.raises(TriageError):
        _decide({"message_id": "<abc@cassandra.apache.org>"})


def test_missing_message_id_is_rejected():
    with pytest.raises(TriageError):
        _decide({"action": "accept"})


def test_report_from_another_project_is_not_found():
    with pytest.raises(TriageError) as e:
        _decide({"message_id": "<somewhere-else@kafka.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"})
    assert e.value.status == 404


def test_report_in_a_state_without_a_form_cannot_be_triaged():
    with pytest.raises(TriageError) as e:
        _decide(
            {"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"},
            candidates=[_report(state="confirmed")],
        )
    assert e.value.status == 409


def test_overlong_feedback_is_rejected():
    with pytest.raises(TriageError) as e:
        _decide({
            "message_id": "<abc@cassandra.apache.org>",
            "tag": "2024-03-01 a flaw",
            "action": "accept",
            "feedback": "x" * (triage.MAX_FEEDBACK_LENGTH + 1),
        })
    assert e.value.status == 413


def test_non_text_feedback_is_rejected():
    with pytest.raises(TriageError):
        _decide({"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw", "feedback": {"a": 1}})


def test_untriaged_has_a_form_and_other_states_do_not():
    assert triage.form_template("cassandra", "untriaged") == "includes/forms/untriaged.html"
    assert triage.form_template("cassandra", "confirmed") is None
    assert triage.form_template("cassandra", "non-issue-docs") is None


def test_a_project_that_has_not_asked_for_triage_gets_no_form(monkeypatch):
    _config(monkeypatch, pmcs_with_triage=["kafka"])
    assert triage.form_template("cassandra", "untriaged") is None


def test_triage_is_off_for_a_project_that_has_not_asked_for_it(monkeypatch):
    _config(monkeypatch, pmcs_with_triage=["kafka"])
    assert not triage.enabled_for("cassandra")
    assert triage.enabled_for("kafka")


def test_a_decision_for_a_project_that_has_not_asked_for_triage_is_refused(monkeypatch):
    _config(monkeypatch, pmcs_with_triage=[])
    with pytest.raises(TriageError) as e:
        _decide({"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"})
    assert e.value.status == 404


class _FakeResponse:
    """Just enough of an aiohttp response for `submit`."""

    def __init__(self, status: int = 200, body: str = ""):
        self.status = status
        self._body = body

    async def text(self):
        return self._body

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


class _FakeSession:
    def __init__(self, posts, response=None, error=None):
        self._posts = posts
        self._response = response or _FakeResponse()
        self._error = error

    def post(self, url, json):
        self._posts.append((url, json))
        if self._error is not None:
            raise self._error
        return self._response

    async def __aenter__(self):
        return self

    async def __aexit__(self, *exc):
        return False


def _submit(monkeypatch, payload, response=None, error=None, backend="http://backend:5002"):
    """Run `submit` against a fake notification API; returns the posts it made."""
    posts = []
    _config(monkeypatch, backend=backend)
    monkeypatch.setattr(
        triage.aiohttp,
        "ClientSession",
        lambda **kwargs: _FakeSession(posts, response=response, error=error),
    )
    asyncio.run(triage.submit(_decide(payload)))
    return posts


def test_submit_posts_an_accept_report_to_the_notification_api(monkeypatch):
    posts = _submit(monkeypatch, {
        "message_id": "<abc@cassandra.apache.org>",
        "action": "accept",
        "tag": "2024-03-01 a flaw",
        "feedback": "Thanks, we agree this is a vulnerability.",
    })

    assert posts == [(
        "http://backend:5002/triage/accept",
        {
            "sender": "jdoe",
            "sender_name": "John Doe",
            "pmc": "cassandra",
            "tag": "2024-03-01 a flaw",
            "message_id": "<abc@cassandra.apache.org>",
            "response": "Thanks, we agree this is a vulnerability.",
        },
    )]


def test_submit_posts_a_reject_report_to_the_reject_endpoint(monkeypatch):
    posts = _submit(monkeypatch, {"message_id": "<abc@cassandra.apache.org>", "action": "reject", "tag": "2024-03-01 a flaw"})

    url, body = posts[0]
    assert url == "http://backend:5002/triage/reject"
    assert body["response"] == ""


def test_submit_does_not_double_the_slash_of_a_backend_url(monkeypatch):
    posts = _submit(
        monkeypatch,
        {"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"},
        backend="http://backend:5002/",
    )

    assert posts[0][0] == "http://backend:5002/triage/accept"


def test_submit_reports_a_refusal_by_the_notification_api(monkeypatch):
    with pytest.raises(TriageUnavailable):
        _submit(
            monkeypatch,
            {"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"},
            response=_FakeResponse(status=500, body="boom"),
        )


def test_submit_reports_a_notification_api_it_cannot_reach(monkeypatch):
    with pytest.raises(TriageUnavailable):
        _submit(
            monkeypatch,
            {"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"},
            error=triage.aiohttp.ClientConnectionError("refused"),
        )


def test_submit_reports_a_notification_api_that_does_not_answer_in_time(monkeypatch):
    with pytest.raises(TriageUnavailable):
        _submit(
            monkeypatch,
            {"message_id": "<abc@cassandra.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"},
            error=asyncio.TimeoutError(),
        )


def _preview(report=None, project="cassandra", monkeypatch=None, security_lists=(), signatory="J. Doe"):
    if monkeypatch is not None:
        _config(monkeypatch, pmcs_with_security_emails=list(security_lists))
    return triage.message_preview(project, report or _report(), signatory)


def test_preview_is_addressed_to_the_reporter():
    report = dataclasses.replace(_report(), reporter=Reporter(name="Jane Reporter", email="jane@aisle.com"))
    assert _preview(report).to == "Jane Reporter <jane@aisle.com>"


def test_preview_falls_back_when_the_reporter_is_unknown():
    preview = _preview(dataclasses.replace(_report(), reporter=None))
    assert preview.to == "the reporter"
    assert preview.salutation == "Dear reporter,"


def test_preview_ccs_the_pmc_security_list_when_it_has_one(monkeypatch):
    preview = _preview(monkeypatch=monkeypatch, security_lists=["cassandra"])
    assert preview.cc == ("security@cassandra.apache.org",)


def test_preview_ccs_the_security_team_and_private_list_without_a_security_list(monkeypatch):
    preview = _preview(monkeypatch=monkeypatch, security_lists=["airflow"])
    assert preview.cc == ("security@apache.org", "private@cassandra.apache.org")


def test_preview_replies_to_the_report_subject():
    assert _preview().subject == "Re: a flaw"


def test_preview_has_a_paragraph_for_each_action():
    decisions = _preview().decisions
    assert set(decisions) == {"accept", "reject"}
    assert "Cassandra" in decisions["reject"]
    assert all(text for text in decisions.values())


def test_preview_is_signed_by_the_pmc_member_taking_the_decision():
    assert _preview(signatory="J. Doe").closing == (
        "Kind regards,\nJ. Doe\nPMC member for Apache Cassandra"
    )
