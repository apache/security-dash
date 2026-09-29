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

"""End-to-end tests of the incubator view, which summarizes the podlings."""

import pytest
import re

from app.test_project_view import _CONFIG, _build_app, _login, _write_report, sync

_PODLINGS = """\
pmcs_in_incubator: [alpha, beta, gamma, delta]
"""


@pytest.fixture
def quart_app(tmp_path, monkeypatch):
    data_dir = tmp_path / "data"
    # alpha: 1 untriaged of 1; beta: 2 of 2; gamma: 1 of 3; delta: none
    _write_report(data_dir, "alpha", "2024-03-01 a flaw")
    _write_report(data_dir, "beta", "2024-03-01 a flaw")
    _write_report(data_dir, "beta", "2024-03-02 another flaw")
    _write_report(data_dir, "gamma", "2024-03-01 a flaw")
    _write_report(data_dir, "gamma", "CVE-2024-1234 a flaw")
    _write_report(data_dir, "gamma", "CVE-2024-5678 another flaw")
    return _build_app(tmp_path, monkeypatch, config=_CONFIG + _PODLINGS)


async def _incubator_page(quart_app, monkeypatch):
    _login(monkeypatch, committees=("incubator",))
    response = await quart_app.test_client().get("/project/incubator")
    assert response.status_code == 200
    return await response.get_data(as_text=True)


def _summary(body):
    return body[body.index('<table class="reports-table incubator-table'):body.index("</table>")]


@sync
async def test_summary_is_sorted_by_untriaged_then_total(quart_app, monkeypatch):
    body = await _incubator_page(quart_app, monkeypatch)

    assert re.findall(r'<td><a href="#(\w+)">', _summary(body)) == ["beta", "gamma", "alpha", "delta"]


@sync
async def test_summary_counts_untriaged_and_total_reports(quart_app, monkeypatch):
    body = await _incubator_page(quart_app, monkeypatch)
    rows = _summary(body).split("<tr>")[2:]
    gamma = next(row for row in rows if 'href="#gamma"' in row)
    delta = next(row for row in rows if 'href="#delta"' in row)

    assert '<a href="#gamma-untriaged">1</a>' in gamma
    assert '<td class="incubator-count">3</td>' in gamma
    assert "<td>2023-11-14</td>" in gamma
    assert '<td class="incubator-count">0</td>' in delta
    assert "<td></td>" in delta


@sync
async def test_podling_reports_are_listed_under_anchors(quart_app, monkeypatch):
    body = await _incubator_page(quart_app, monkeypatch)

    assert '<h2 id="gamma">gamma</h2>' in body
    assert '<h3 id="gamma-untriaged">' in body
    assert '<h3 id="gamma-confirmed">' in body
    assert "No open security reports." in body[body.index('<h2 id="delta">'):]


@sync
async def test_incubator_view_has_no_triage_forms(quart_app, monkeypatch):
    """Triage is authorized per podling, so it is done from the podling's own page."""
    body = await _incubator_page(quart_app, monkeypatch)

    assert "/triage" not in body


@sync
async def test_project_view_sections_have_anchors(quart_app, monkeypatch):
    _login(monkeypatch, committees=("cassandra",))
    response = await quart_app.test_client().get("/project/cassandra")
    body = await response.get_data(as_text=True)

    assert '<h3 id="untriaged">' in body
