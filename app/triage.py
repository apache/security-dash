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

"""Triage decisions a PMC can take on a report from the project view.

The dashboard does not change report state itself: a decision is handed to the
notification API, which emails the feedback to the reporter and moves the report
on (rejected reports end up in the zzz-non-issue tree, so they drop off this
dashboard entirely).

Which form a report gets, and which actions that form may submit, depend on the
state the report is in: both live in `_STATE_FORMS` below, so adding a form for
another state is a matter of adding an entry and a template.

Triage is opt-in per PMC (`pmcs_with_triage` in the config), since a decision
mails the reporter: `enabled_for` gates both the form and the endpoint.
"""

from app import config
from app.reports import Report
import aiohttp
import asyncio
import dataclasses
import datetime
import enum
from typing import Mapping
import urllib

class TriageAction(enum.StrEnum):
    ACCEPT = "accept"
    REJECT = "reject"

@dataclasses.dataclass(frozen=True)
class _StateForm:
    template: str
    actions: frozenset[TriageAction]

_STATE_FORMS: dict[str, _StateForm] = {
    "untriaged": _StateForm(
        template="includes/forms/untriaged.html",
        actions=frozenset({TriageAction.ACCEPT, TriageAction.REJECT}),
    ),
}

MAX_FEEDBACK_LENGTH = 10_000

# The notification API owns the real email template; these are the static parts
# of it, so the PMC can see what the reporter will receive before submitting.
# TODO: they are a copy, and have to be kept in step with that API by hand.
# Better, once it exists: have it render the preview and fetch it from here.
_SALUTATION = "Dear {reporter},"
_OPENING = "Thank you for your report."
_DECISION_PARAGRAPHS: dict[TriageAction, str] = {
    TriageAction.ACCEPT: (
        "The PMC has confirmed the issue you reported as a vulnerability and is "
        "working on a fix. You will be notified once a release containing the fix "
        "is available, and are asked to keep the report confidential until then."
    ),
    TriageAction.REJECT: (
        "The PMC has determined that the issue you reported is not a vulnerability "
        "in Apache {project}."
    ),
}
_CLOSING_GREETING = "Kind regards,"
_CLOSING_PMC = "PMC member for Apache {project}"

@dataclasses.dataclass(frozen=True)
class MessagePreview:
    """What the reporter will receive, around the PMC's own feedback."""
    to: str
    cc: tuple[str, ...]
    subject: str
    salutation: str
    opening: str
    decisions: dict[str, str]
    """The paragraph each action produces, keyed by action value."""
    closing: str
    """Sign-off, naming the PMC member who took the decision."""

def _cc_addresses(project: str) -> tuple[str, ...]:
    """The lists kept in the loop on the reply."""
    if project in config.get().pmcs_with_security_emails:
        return (f"security@{project}.apache.org",)
    return ("security@apache.org", f"private@{project}.apache.org")

def _closing(project: str, signatory: str) -> str:
    lines = [_CLOSING_GREETING]
    if signatory:
        lines.append(signatory)
    lines.append(_CLOSING_PMC.format(project=_display_project(project)))
    return "\n".join(lines)

def _display_project(project: str) -> str:
    """Project ids are lowercase; the API's own template is what finally decides
    how the project is named in the email."""
    return project.capitalize()

def message_preview(project: str, report: Report, signatory: str = "") -> MessagePreview:
    """The email the notification API will send once `report` is triaged.

    `signatory` is the name the decision goes out under: the PMC member filling
    in the form.
    """
    return MessagePreview(
        to=report.reporter.tooltip if report.reporter else "the reporter",
        cc=_cc_addresses(project),
        subject=f"Re: {report.title}",
        salutation=_SALUTATION.format(
            reporter=report.reporter.display_name if report.reporter else "reporter"
        ),
        opening=_OPENING.format(project=_display_project(project)),
        decisions={
            action.value: paragraph.format(project=_display_project(project))
            for action, paragraph in _DECISION_PARAGRAPHS.items()
        },
        closing=_closing(project, signatory),
    )

CONFIRMATION_MESSAGES: dict[TriageAction, str] = {
    TriageAction.ACCEPT: "Thanks for triaging and accepting this report! Notification emails have been sent, please allow for a day or so before this acceptance is reflected in this dashboard.",
    TriageAction.REJECT: "Thanks for triaging and rejecting this report!  Notification emails have been sent, please allow for a day or so before this acceptance is reflected in this dashboard."
}

class TriageError(Exception):
    """The submitted decision was not something we can act on."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.message = message
        self.status = status

class TriageUnavailable(Exception):
    """The decision was valid, but could not be handed to the notification API."""

def enabled_for(project: str) -> bool:
    """Whether `project` takes its triage decisions through this dashboard."""
    return project in config.get().pmcs_with_triage

def form_template(project: str, state: str) -> str | None:
    """The form to show for a report of `project` in `state`.

    None when the project has not asked for triage, or the state has no form.
    """
    if not enabled_for(project):
        return None
    form = _STATE_FORMS.get(state)
    return form.template if form else None

@dataclasses.dataclass(frozen=True)
class TriageDecision:
    project: str
    report: Report
    action: TriageAction
    feedback: str
    """Feedback for the reporter, as typed by the PMC. May be empty."""
    uid: str
    """ASF id of the user who took the decision."""
    name: str
    """Full name of the user who took the decision."""
    at: datetime.datetime

def _required_string(payload: Mapping[str, object], field: str) -> str:
    value = payload.get(field)
    if not isinstance(value, str) or not value.strip():
        raise TriageError(f"missing '{field}'")
    return value.strip()

def parse_decision(
    project: str,
    candidates: list[Report],
    payload: Mapping[str, object],
    uid: str,
    name: str,
    now: datetime.datetime | None = None,
) -> TriageDecision:
    """Validate a submitted form or API payload against the project's reports.

    The report is looked up among `candidates` rather than trusted from the
    payload, so a decision can only ever apply to a report of the project the
    user was authorized for, in a state that has a form.
    """
    if not enabled_for(project):
        raise TriageError(f"{project} does not take triage decisions here", status=404)

    message_id = _required_string(payload, "message_id")
    tag = _required_string(payload, "tag")
    raw_action = _required_string(payload, "action")
    try:
        action = TriageAction(raw_action)
    except ValueError:
        raise TriageError(f"unknown action: {raw_action!r}")

    matches = [report for report in candidates if report.message_id == message_id and report.security_team_name == tag]
    if not matches:
        raise TriageError(f"no report {message_id!r} in {project}", status=404)
    if len(matches) > 1:
        raise TriageError(f"report {message_id!r} in {project} not unique", status=400)
    report = matches[0]

    form = _STATE_FORMS.get(report.state)
    if form is None:
        raise TriageError(
            f"report {message_id!r} is in state {report.state!r}, which cannot be triaged",
            status=409,
        )
    if action not in form.actions:
        raise TriageError(
            f"cannot {action} a report in state {report.state!r}",
            status=409,
        )

    feedback = payload.get("feedback") or ""
    if not isinstance(feedback, str):
        raise TriageError("'feedback' must be text")
    feedback = feedback.strip()
    if len(feedback) > MAX_FEEDBACK_LENGTH:
        raise TriageError(f"feedback is longer than {MAX_FEEDBACK_LENGTH} characters", status=413)

    return TriageDecision(
        project=project,
        report=report,
        action=action,
        feedback=feedback,
        uid=uid,
        name=name,
        at=now or datetime.datetime.now(tz=datetime.timezone.utc),
    )

@dataclasses.dataclass(frozen=True)
class AcceptReport:
    """Body of a POST to the notification API's accept endpoint."""
    sender: str
    """ASF id of the PMC member who took the decision."""
    sender_name: str
    """Full name of the PMC member who took the decision."""
    pmc: str
    """The PMC for this report"""
    tag: str
    """The label the security team gave the thread."""
    message_id: str
    response: str
    """Feedback for the reporter; may be empty."""

@dataclasses.dataclass(frozen=True)
class RejectReport:
    """Body of a POST to the notification API's reject endpoint."""
    sender: str
    """ASF id of the PMC member who took the decision."""
    sender_name: str
    """Full name of the PMC member who took the decision."""
    pmc: str
    """The PMC for this report"""
    tag: str
    """The label the security team gave the thread."""
    message_id: str
    response: str
    """Feedback for the reporter; may be empty."""

_ENDPOINTS: dict[TriageAction, tuple[str, type]] = {
    TriageAction.ACCEPT: ("/triage/accept", AcceptReport),
    TriageAction.REJECT: ("/triage/reject", RejectReport),
}

SUBMIT_TIMEOUT_SECONDS = 30

_UNAVAILABLE = (
    "The decision could not be handed to the notification API, so the reporter "
    "was not notified. Please try again, or email security@apache.org."
)

async def submit(decision: TriageDecision) -> None:
    """Hand `decision` to the notification API.

    That API emails the feedback to the reporter and moves the report on, so a
    decision it did not accept has had no effect at all: any failure to reach it,
    or any answer other than success, is reported back as TriageUnavailable.
    """
    path, report_type = _ENDPOINTS[decision.action]
    url = config.get().backend.rstrip("/") + path
    report = report_type(
        sender=decision.uid,
        sender_name=decision.name,
        pmc=decision.project,
        tag=decision.report.security_team_name,
        message_id=decision.report.message_id,
        response=decision.feedback,
    )

    timeout = aiohttp.ClientTimeout(total=SUBMIT_TIMEOUT_SECONDS)
    try:
        async with aiohttp.ClientSession(timeout=timeout) as session:
            async with session.post(url, json=dataclasses.asdict(report)) as response:
                if response.status >= 400:
                    body = (await response.text()).strip()
                    print(
                        f"Notification API refused {decision.action} of "
                        f"{decision.report.security_team_name!r}: "
                        f"{response.status} {body[:5000]}"
                    )
                    raise TriageUnavailable(_UNAVAILABLE)
    except (aiohttp.ClientError, asyncio.TimeoutError) as e:
        print(f"Notification API at {url} could not be reached: {e!r}")
        raise TriageUnavailable(_UNAVAILABLE) from e
