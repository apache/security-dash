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

"""End-to-end tests of the project view and its triage endpoint."""

import asfquart
import asyncio
import functools
import json
import pytest
import types

import app as app_module

MESSAGE_ID = "<abc@cassandra.apache.org>"


def sync(test):
    """Run an async test on its own loop; the suite has no pytest-asyncio."""
    @functools.wraps(test)
    def wrapper(*args, **kwargs):
        return asyncio.run(test(*args, **kwargs))
    return wrapper

_CONFIG = """\
data_dir: {data_dir}
state_dir: {state_dir}
old_cve_close_dates: {{}}
pmcs_with_triage:
  - cassandra
"""


def _write_report(data_dir, pmc, label, *, message_id=MESSAGE_ID):
    pmc_dir = data_dir / pmc
    pmc_dir.mkdir(parents=True, exist_ok=True)
    (pmc_dir / f"{label}.json").write_text(json.dumps([
        {
            "subj": "[SECURITY] a flaw",
            "from": "Jane Reporter <jane@aisle.com>",
            "to": f"security@{pmc}.apache.org",
            "message_id": message_id,
            "mailtime": 1700000000,
        }
    ]))


def _build_app(tmp_path, monkeypatch, label="2024-03-01 a flaw", extra="", config=None):
    data_dir = tmp_path / "data"
    _write_report(data_dir, "cassandra", label)
    (tmp_path / "config.yaml").write_text(
        (config or _CONFIG).format(data_dir=data_dir, state_dir=tmp_path / "state") + extra
    )
    monkeypatch.chdir(tmp_path)
    return app_module.create_app(test_environment=True)


@pytest.fixture
def quart_app(tmp_path, monkeypatch):
    return _build_app(tmp_path, monkeypatch)


@pytest.fixture
def quart_app_without_triage(tmp_path, monkeypatch):
    """A project that has not asked to take its decisions here."""
    config = _CONFIG.replace("pmcs_with_triage:\n  - cassandra\n", "")
    return _build_app(tmp_path, monkeypatch, config=config)


def _login(monkeypatch, uid="jdoe", fullname="J. Doe", committees=("cassandra",), projects=()):
    async def read(*args, **kwargs):
        return types.SimpleNamespace(
            uid=uid,
            fullname=fullname,
            committees=list(committees),
            projects=list(projects),
            isRoot=False,
        )
    monkeypatch.setattr(asfquart.session, "read", read)


def _anonymous(monkeypatch):
    async def read(*args, **kwargs):
        return None
    monkeypatch.setattr(asfquart.session, "read", read)


async def _triage(client, data, **kwargs):
    return await client.post("/api/project/cassandra/triage", form=data, **kwargs)


@pytest.fixture(autouse=True)
def notification_api(monkeypatch):
    """Stand in for the notification API: record what triage hands it.

    Set `unavailable` to have it fail the way an unreachable API does.
    """
    api = types.SimpleNamespace(decisions=[], unavailable=None)

    async def submit(decision):
        api.decisions.append(decision)
        if api.unavailable:
            raise app_module.triage.TriageUnavailable(api.unavailable)

    monkeypatch.setattr(app_module.triage, "submit", submit)
    return api


@sync
async def test_untriaged_report_gets_a_triage_form(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert 'action="/api/project/cassandra/triage"' in body
    assert 'name="message_id" value="&lt;abc@cassandra.apache.org&gt;"' in body
    assert 'type="radio" name="action" value="accept"' in body
    assert 'type="radio" name="action" value="reject"' in body
    assert body.count('type="submit"') == 1


@sync
async def test_a_project_without_triage_gets_no_form(quart_app_without_triage, monkeypatch):
    _login(monkeypatch)
    response = await quart_app_without_triage.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "a flaw" in body
    assert "/api/project/cassandra/triage" not in body
    assert '<td class="reports-triage">' not in body


@sync
async def test_a_project_without_triage_refuses_a_decision(
    quart_app_without_triage, monkeypatch, notification_api
):
    """The opt-in gates the endpoint too, not just the form."""
    _login(monkeypatch)
    response = await quart_app_without_triage.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": MESSAGE_ID, "action": "accept"},
    )

    assert response.status_code == 404
    assert notification_api.decisions == []


@sync
async def test_triage_control_sits_in_the_report_row(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)
    table = body[body.index('<table class="reports-table">'):body.index("</table>")]

    assert '<td class="reports-triage">' in table
    # one row per report: the form is a cell of it, not a row of its own
    assert table.count("<tr>") == 1


@sync
async def test_project_view_loads_the_triage_script(quart_app, monkeypatch):
    """The preview is revealed by triage.js, so the page has to pull it in."""
    _login(monkeypatch)
    client = quart_app.test_client()
    body = await (await client.get("/project/cassandra")).get_data(as_text=True)

    assert '<script src="/assets/js/triage.js"></script>' in body
    assert (await client.get("/assets/js/triage.js")).status_code == 200


@sync
async def test_triage_form_previews_the_email_to_the_reporter(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert "Jane Reporter &lt;jane@aisle.com&gt;" in body
    # cassandra has no dedicated security list in this config
    assert "security@apache.org, private@cassandra.apache.org" in body
    assert "Re: a flaw" in body
    # both decision paragraphs are rendered; CSS shows the selected one
    assert "confirmed the issue you reported as a vulnerability" in body
    assert "is not a vulnerability in Apache Cassandra" in body
    assert "Kind regards,\nJ. Doe\nPMC member for Apache Cassandra" in body


@sync
async def test_preview_falls_back_to_the_asf_id_when_the_name_is_unknown(quart_app, monkeypatch):
    _login(monkeypatch, fullname=None)
    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert "Kind regards,\njdoe\nPMC member for Apache Cassandra" in body


@sync
async def test_confirmed_report_gets_no_form(tmp_path, monkeypatch):
    quart_app = _build_app(tmp_path, monkeypatch, label="CVE-2024-1234 a flaw")
    _login(monkeypatch)

    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "Triage this report" not in body


@sync
async def test_preview_ccs_a_dedicated_security_list_when_the_pmc_has_one(tmp_path, monkeypatch):
    quart_app = _build_app(
        tmp_path, monkeypatch, extra="pmcs_with_security_emails:\n  - cassandra\n"
    )
    _login(monkeypatch)

    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert "<dd>security@cassandra.apache.org</dd>" in body
    assert "private@cassandra.apache.org" not in body


@sync
async def test_form_post_redirects_back_to_the_project_view(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await _triage(
        quart_app.test_client(),
        {"message_id": MESSAGE_ID, "action": "accept", "tag": "2024-03-01 a flaw", "feedback": "agreed"},
    )

    assert response.status_code == 303
    assert response.headers["Location"].endswith("/project/cassandra")


@sync
async def test_form_post_hands_the_decision_to_the_notification_api(quart_app, monkeypatch, notification_api):
    _login(monkeypatch)
    await _triage(
        quart_app.test_client(),
        {"message_id": MESSAGE_ID, "action": "accept", "tag": "2024-03-01 a flaw", "feedback": "agreed"},
    )

    decision = notification_api.decisions[0]
    assert decision.action is app_module.triage.TriageAction.ACCEPT
    assert decision.feedback == "agreed"
    assert decision.uid == "jdoe"
    assert decision.report.message_id == MESSAGE_ID


@sync
async def test_form_post_outcome_is_shown_on_the_project_view(quart_app, monkeypatch):
    _login(monkeypatch)
    client = quart_app.test_client()
    response = await _triage(
        client,
        {"message_id": MESSAGE_ID, "action": "accept", "tag": "2024-03-01 a flaw", "feedback": "agreed"},
        follow_redirects=True,
    )
    body = await response.get_data(as_text=True)

    assert response.status_code == 200
    assert "banner-success" in body
    assert "Thanks for triaging and accepting this report" in body


@sync
async def test_form_post_says_so_when_the_notification_api_is_unavailable(
    quart_app, monkeypatch, notification_api
):
    _login(monkeypatch)
    notification_api.unavailable = "the notification API could not be reached"
    response = await _triage(
        quart_app.test_client(),
        {"message_id": MESSAGE_ID, "action": "accept", "tag": "2024-03-01 a flaw", "feedback": "agreed"},
        follow_redirects=True,
    )
    body = await response.get_data(as_text=True)

    # the user is told on the page they came from rather than on an error page
    assert response.status_code == 200
    assert "banner-error" in body
    assert "the notification API could not be reached" in body


@sync
async def test_api_call_gets_json(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await quart_app.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": MESSAGE_ID, "action": "accept", "tag": "2024-03-01 a flaw", "feedback": "agreed"},
    )

    assert response.status_code == 200
    assert (await response.get_json())["status"] == "success"


@sync
async def test_api_call_rejects_an_unknown_action(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await quart_app.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": MESSAGE_ID, "action": "delete"},
    )

    assert response.status_code == 400


@sync
async def test_api_call_rejects_a_report_of_another_project(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await quart_app.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": "<elsewhere@kafka.apache.org>", "action": "accept", "tag": "2024-03-01 a flaw"},
    )

    assert response.status_code == 404


@sync
async def test_triage_requires_membership_of_the_pmc(quart_app, monkeypatch):
    _login(monkeypatch, committees=("kafka",))
    response = await quart_app.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": MESSAGE_ID, "action": "accept"},
    )

    assert response.status_code == 403


@sync
async def test_triage_requires_a_login(quart_app, monkeypatch):
    _anonymous(monkeypatch)
    response = await quart_app.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": MESSAGE_ID, "action": "accept"},
    )

    # anonymous callers are bounced into the OAuth login, as on the other endpoints
    assert response.status_code == 302


@sync
async def test_cross_site_form_post_is_refused(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await _triage(
        quart_app.test_client(),
        {"message_id": MESSAGE_ID, "action": "accept"},
        headers={"Sec-Fetch-Site": "cross-site"},
    )

    assert response.status_code == 403


@sync
async def test_same_site_form_post_is_refused(quart_app, monkeypatch):
    """Another apache.org app is same-site, which SameSite=Strict would allow."""
    _login(monkeypatch)
    response = await _triage(
        quart_app.test_client(),
        {"message_id": MESSAGE_ID, "action": "accept"},
        headers={"Sec-Fetch-Site": "same-site"},
    )

    assert response.status_code == 403


@sync
async def test_same_origin_form_post_is_accepted(quart_app, monkeypatch):
    _login(monkeypatch)
    response = await _triage(
        quart_app.test_client(),
        {"message_id": MESSAGE_ID, "action": "accept"},
        headers={"Sec-Fetch-Site": "same-origin"},
    )

    assert response.status_code == 303


@sync
async def test_post_without_fetch_metadata_is_accepted(quart_app, monkeypatch):
    """API clients send no Sec-Fetch-Site; they are authenticated as usual."""
    _login(monkeypatch)
    response = await quart_app.test_client().post(
        "/api/project/cassandra/triage",
        json={"message_id": MESSAGE_ID, "action": "accept", "tag": "2024-03-01 a flaw"},
    )

    assert response.status_code == 200
