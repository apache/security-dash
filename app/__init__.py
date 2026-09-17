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

"""Security issue dashboard for the Apache Software Foundation"""

from app import reports, statistics, triage, utils
from app.config import AppConfig
import asfquart
import asfquart.auth
import datetime
import os
import pathlib
from typing import Any
import quart

def _ensure_state_dir(app_config: AppConfig) -> None:
    state_dir_path = app_config.state_dir_path
    if not state_dir_path.exists():
        state_dir_path.mkdir(parents=True)
    elif not state_dir_path.is_dir():
        raise NotADirectoryError(f"State directory '{state_dir_path}' is not a directory")

CLIENT = quart.Blueprint(
        "client",
        __name__,
        static_folder="static/assets",
        static_url_path="/assets",
        template_folder="templates",
        url_prefix="/",
)

@CLIENT.route("/")
async def home():
    user = await utils.UserSession.create()
    if user.is_authenticated and len(user.accessible_pmcs) == 1:
        return quart.redirect(quart.url_for("client.project", project=user.accessible_pmcs[0]))
    return await quart.render_template("home.html")

def _state_sort_key(state: str) -> tuple[int, str]:
    if state == "untriaged":
        return (0, "")
    elif state == "confirmed":
        return (1, "")
    elif state == "disclosure":
        return (3, "")
    elif state.startswith("non-issue"):
        return (4, state)
    else:
        return (2, state)

_STATE_TITLES: dict[str, str] = {
    "untriaged": "Untriaged",
    "confirmed": "Confirmed",
    "disclosure": "Waiting for disclosure",
    "non-issue-docs": "Non-issue: pending documentation improvements",
    "non-issue-feedback": "Non-issue: pending feedback to reporter",
    "non-issue-upstream": "Non-issue: pending upstream",
}
_STATE_DESCRIPTIONS: dict[str, str] = {
    "untriaged": "Triage of incoming security reports should happen fairly quickly, because it's the phase in which the PMC decides whether this is an urgent issue. Triage is complete when the PMC decides whether issue is a vulnerability and provides that feedback to the reporter.",
    "confirmed": "The PMC has accepted and is working on these issues. For those that don't have CVEs allocated yet, this can be done now",
    "disclosure": "A fix for these issues has been released. When you are happy with the advisory in the cveprocess tool, you can send them by moving the state to READY and using the 'Send these Emails' button on the 'OSS/ASF Emails' tab in cveprocess.",
    "non-issue-upstream": "Make sure the issue is fixed upstream and a release is made with the fix, or find an alternative to the problematic upstream component",
}

def _state_title(state: str) -> str:
    if state in _STATE_TITLES:
        return _STATE_TITLES[state]
    if state.startswith("non-issue-"):
        return f"Non-issues: {state.removeprefix('non-issue-')}"
    return f"Waiting for {state}"

def _state_description(state: str) -> str:
    return _STATE_DESCRIPTIONS.get(state, "")

def _asf_group_acl(project, pmc_membership, project_membership):
    return (
        project in pmc_membership
        or (
            project in config.get().pmcs_with_security_emails
            and project in project_membership
        )
    )

async def _require_authorization_for(project: str) -> utils.UserSession:
    user = await utils.UserSession.create()
    if not user.is_authenticated:
        raise asfquart.auth.AuthenticationFailed(asfquart.auth.Requirements.E_NOT_LOGGED_IN)
    pmcs = user.accessible_pmcs
    if (not _asf_group_acl(project, pmcs, user.projects)
        and not _asf_group_acl("security", pmcs, user.projects)):
        raise asfquart.auth.AuthenticationFailed(f"You are not a member of the {project} PMC.")
    return user

async def _require_authentication() -> utils.UserSession:
    user = await utils.UserSession.create()
    if not user.is_authenticated:
        raise asfquart.auth.AuthenticationFailed(asfquart.auth.Requirements.E_NOT_LOGGED_IN)
    return user

@CLIENT.route("/statistics")
async def statistics_dashboard():
    await _require_authentication()
    return await quart.render_template("statistics.html", debt_constant=statistics.DEBT_CONSTANT)

@CLIENT.route("/api/statistics/debt")
async def statistics_debt_api():
    user = await _require_authentication()

    requested_pmcs = {
        pmc.strip()
        for pmc in quart.request.args.getlist("pmc")
    }

    if requested_pmcs:
        for pmc in requested_pmcs:
            if pmc not in user.accessible_pmcs and not user.in_security_team:
                quart.abort(403)

    # security team members see every project; everyone else sees only the
    # projects they can access (the same set shown on their front page).
    if requested_pmcs:
        pmcs = requested_pmcs
    elif user.in_security_team:
        pmcs = None
    elif user.accessible_pmcs:
        pmcs = user.accessible_pmcs
    else:
        quart.abort(403)
    now = datetime.datetime.now(tz=datetime.timezone.utc)
    return quart.jsonify(statistics.compute_debt_chart(now, pmcs=pmcs))

async def _audit_access(project: str):
    user = await utils.UserSession.create()

    # Out-of-PMC access, such as security team or other admin
    # access, is OK but logged with more scrutiny
    mark = "" if project in user.pmcs else "[*]"

    print(f"User {user.uid} accessed project {project}{mark}")

@CLIENT.route("/project/<project>")
async def project(project: str):
    await _require_authorization_for(project)
    await _audit_access(project)
    r = await reports.load_pmc_reports(project)
    states = sorted(dict.fromkeys(report.state for report in r), key=_state_sort_key)
    sections = [
        (
            _state_title(state),
            _state_description(state),
            triage.form_template(project, state),
            [report for report in r if report.state == state],
        )
        for state in states
    ]
    return await quart.render_template("project.html",
        project_name=project,
        debt_constant=statistics.DEBT_CONSTANT,
        sections=sections,
        max_feedback_length=triage.MAX_FEEDBACK_LENGTH,
        message_preview=triage.message_preview,
        show_subproject=project in config.get().pmcs_with_subprojects or project == "security")

@CLIENT.route("/api/project/<project>/reports")
async def project_reports_api(project: str):
    await _require_authorization_for(project)
    await _audit_access(project)
    r = await reports.load_pmc_reports(project)
    return quart.jsonify([
        {
            "cves": report.cves,
            "title": report.title,
            "message_id": report.message_id,
            "asf_member_link": report.asf_member_link,
            "state": report.state,
            "date": report.date.isoformat(),
        }
        for report in r
    ])

def _wants_json() -> bool:
    """Whether to answer with JSON (an API call) rather than a redirect (a form post)."""
    if quart.request.is_json:
        return True
    return quart.request.accept_mimetypes.best_match(["text/html", "application/json"]) == "application/json"

def _require_same_origin() -> None:
    """Refuse browser posts that did not come from this origin.

    The session cookie is SameSite=Strict, so a cross-*site* post carries no
    session and fails to authenticate anyway. This narrows that to the origin,
    which SameSite does not do: another apache.org app is same-site but not
    same-origin. Requests without the header (API clients, and browsers too old
    to send Fetch Metadata) are let through and authenticated as usual.
    """
    if quart.request.headers.get("Sec-Fetch-Site") not in (None, "same-origin"):
        quart.abort(403, "CSRF Protection")

async def _triage_payload() -> dict[str, object]:
    if quart.request.is_json:
        payload = await quart.request.get_json()
        if not isinstance(payload, dict):
            raise triage.TriageError("expected a JSON object")
        return payload
    return (await quart.request.form).to_dict()

@CLIENT.route("/api/project/<project>/triage", methods=["POST"])
async def project_triage_api(project: str):
    """Take a triage decision on one report, from the project view or as an API call."""
    user = await _require_authorization_for(project)
    _require_same_origin()

    try:
        payload = await _triage_payload()
        decision = triage.parse_decision(
            project, await reports.load_pmc_reports(project), payload, uid=user.uid, name=user.fullname
        )
        print(f"User {user.uid} triaged {project} report "
              f"{decision.report.security_team_name!r} as {decision.action}")
        await triage.submit(decision)
    except triage.TriageError as e:
        return await _triage_response(project, e.message, "error", e.status)
    except triage.TriageUnavailable as e:
        return await _triage_response(project, str(e), "error", 501)

    return await _triage_response(
        project,
        triage.CONFIRMATION_MESSAGES[decision.action],
        "success",
        200,
        action=decision.action,
        message_id=decision.report.message_id,
    )

async def _triage_response(project: str, message: str, category: str, status: int, **details: Any):
    if _wants_json():
        return quart.jsonify({"status": category, "message": message, **details}), status
    await quart.flash(message, category)
    return quart.redirect(quart.url_for("client.project", project=project), code=303)

def _register_routes(quart_app: asfquart.base.QuartApp) -> None:
    quart_app.register_blueprint(CLIENT)

def _setup_context(quart_app: asfquart.base.QuartApp, app_config: AppConfig) -> None:
    @quart_app.context_processor
    async def app_context() -> dict[str, Any]:
        return {
            "current_user": await utils.UserSession.create()
        }

_CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self'",
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' https://apache.org",
    "connect-src 'self'",
    "frame-ancestors 'none'",
    "base-uri 'none'",
    "form-action 'self'",
])

def _setup_security_headers(quart_app: asfquart.base.QuartApp) -> None:
    @quart_app.after_request
    async def add_security_headers(response: quart.Response) -> quart.Response:
        response.headers.setdefault("Content-Security-Policy", _CSP)
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        return response

def create_app(test_environment: bool = False) -> asfquart.base.QuartApp:
    from app import config
    app_dir = None
    cfg_file = asfquart.base.CONFIG_FNAME

    # load the application config first to determine the state directory
    app_path = pathlib.Path(os.getcwd())
    app_config = config.load_app_config(app_path / cfg_file)

    if not test_environment:
        # ensure the state directory exists before proceeding
        _ensure_state_dir(app_config)
        # store the app secret in the state directory
        token_file = str((app_config.state_dir_path / "apptoken.txt").absolute())
    else:
        # no secret in unit tests
        token_file = None

    quart_app = asfquart.construct("security-dashboard", app_dir, cfg_file, token_file)

    config.setup_app_config(quart_app, app_config)

    _register_routes(quart_app)
    _setup_context(quart_app, app_config)
    _setup_security_headers(quart_app)

    return quart_app
