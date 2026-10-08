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
"""Authorization of the statistics API, which should match the project view."""

import asfquart
import asyncio
import functools
import json
import types

import app as app_module


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
pmcs_with_security_emails: [tomcat]
pmcs_in_incubator: [podling]
"""


def _write_report(data_dir, pmc):
    pmc_dir = data_dir / pmc
    pmc_dir.mkdir(parents=True, exist_ok=True)
    (pmc_dir / "2024-03-01 a flaw.json").write_text(json.dumps([
        {
            "subj": "[SECURITY] a flaw",
            "from": "Jane Reporter <jane@aisle.com>",
            "to": f"security@{pmc}.apache.org",
            "message_id": f"<abc@{pmc}.apache.org>",
            "mailtime": 1700000000,
        }
    ]))


def _build_app(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    for pmc in ("cassandra", "tomcat", "podling"):
        _write_report(data_dir, pmc)
    (tmp_path / "config.yaml").write_text(
        _CONFIG.format(data_dir=data_dir, state_dir=tmp_path / "state"))
    monkeypatch.chdir(tmp_path)
    return app_module.create_app(test_environment=True)


def _login(monkeypatch, committees=(), projects=()):
    async def read(*args, **kwargs):
        return types.SimpleNamespace(
            uid="jdoe",
            fullname="J. Doe",
            committees=list(committees),
            projects=list(projects),
            isRoot=False,
        )
    monkeypatch.setattr(asfquart.session, "read", read)


async def _debt(quart_app, *pmcs):
    query = "&".join(f"pmc={pmc}" for pmc in pmcs)
    response = await quart_app.test_client().get(f"/api/statistics/debt?{query}")
    if response.status_code != 200:
        return response.status_code, None
    body = await response.get_json()
    return response.status_code, [s["name"] for s in body["series"]]


async def _can_open_project(quart_app, project):
    response = await quart_app.test_client().get(f"/api/project/{project}/reports")
    return response.status_code == 200


@sync
async def test_pmc_member_sees_only_their_pmc(tmp_path, monkeypatch):
    quart_app = _build_app(tmp_path, monkeypatch)
    _login(monkeypatch, committees=("cassandra",))

    assert await _debt(quart_app) == (200, ["cassandra"])
    assert await _debt(quart_app, "cassandra") == (200, ["cassandra"])
    assert not await _can_open_project(quart_app, "tomcat")
    assert (await _debt(quart_app, "tomcat"))[0] == 403


@sync
async def test_committer_of_a_pmc_with_security_emails(tmp_path, monkeypatch):
    quart_app = _build_app(tmp_path, monkeypatch)
    _login(monkeypatch, projects=("tomcat",))

    assert await _can_open_project(quart_app, "tomcat")
    assert (await _debt(quart_app))[0] == 403
    assert await _debt(quart_app, "tomcat") == (200, ["tomcat"])


@sync
async def test_incubator_pmc_member_sees_podlings(tmp_path, monkeypatch):
    quart_app = _build_app(tmp_path, monkeypatch)
    _login(monkeypatch, committees=("incubator",))

    assert await _can_open_project(quart_app, "podling")
    assert await _debt(quart_app) == (200, [])
    assert await _debt(quart_app, "podling") == (200, ["podling"])
    assert not await _can_open_project(quart_app, "cassandra")
    assert (await _debt(quart_app, "cassandra"))[0] == 403


@sync
async def test_board_member_sees_every_project(tmp_path, monkeypatch):
    quart_app = _build_app(tmp_path, monkeypatch)
    _login(monkeypatch, committees=("board",))

    assert await _can_open_project(quart_app, "cassandra")
    assert await _debt(quart_app) == (200, ["cassandra", "podling", "tomcat"])
    assert await _debt(quart_app, "cassandra") == (200, ["cassandra"])


@sync
async def test_user_without_access_is_refused(tmp_path, monkeypatch):
    quart_app = _build_app(tmp_path, monkeypatch)
    _login(monkeypatch, projects=("cassandra",))

    assert not await _can_open_project(quart_app, "cassandra")
    assert (await _debt(quart_app))[0] == 403
    assert (await _debt(quart_app, "cassandra"))[0] == 403
