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

"""Security issue dashboard API for the Apache Software Foundation"""

from app.config import AppConfig
from app import config
import asfquart
import dataclasses
from app.mail import accept_email, reject_email, send_email, valid_pmc, valid_sender
import json
import os
import pathlib
import quart
import quart_schema

def _ensure_state_dir(app_config: AppConfig) -> None:
    state_dir_path = app_config.state_dir_path
    if not state_dir_path.exists():
        state_dir_path.mkdir(parents=True)
    elif not state_dir_path.is_dir():
        raise NotADirectoryError(f"State directory '{state_dir_path}' is not a directory")

API = quart.Blueprint(
        "client",
        __name__,
        url_prefix="/",
)

@dataclasses.dataclass
class AcceptReport:
    sender: str
    tag: str
    message_id: str
    response: str

@dataclasses.dataclass
class RejectReport:
    sender: str
    tag: str
    message_id: str
    response: str

def _get_report_info(tag: str, _message_id: str):
    """Path to the report file. Raises if the tag points outside the data directory."""
    data_dir = config.get().data_dir_path.resolve()
    info = pathlib.Path(data_dir, f"{tag}.json").resolve()
    if not info.is_relative_to(data_dir):
        raise ValueError(f"Report tag escapes the data directory: {tag!r}")
    return info

@API.route("/triage/accept", methods=["POST"])
@quart_schema.validate_request(AcceptReport)
async def accept(data: AcceptReport):
    if not valid_pmc(data.tag.split("/", 1)[0]):
        quart.abort(400, "Invalid PMC")
        return
    if not valid_sender(data.sender):
        quart.abort(400, "Invalid sender")
        return
    info = _get_report_info(data.tag, data.message_id)
    if not info.exists():
        quart.abort(404)
        return
    with open(info) as f:
        js = json.loads(f.read())
        report = js[0]

    email = accept_email(data, report)
    ok = await send_email(email)
    if ok:
        return quart.jsonify({'success': True})
    else:
        quart.abort(500)
        return

@API.route("/triage/reject", methods=["POST"])
@quart_schema.validate_request(RejectReport)
async def reject(data: RejectReport):
    if not valid_pmc(data.tag.split("/", 1)[0]) or not valid_sender(data.sender):
        quart.abort(400)
        return
    info = _get_report_info(data.tag, data.message_id)
    if not info.exists():
        quart.abort(404)
        return
    with open(info) as f:
        js = json.loads(f.read())
        report = js[0]

    email = reject_email(data, report)
    ok = await send_email(email)
    if ok:
        return quart.jsonify({'success': True})
    else:
        quart.abort(500)
        return


def _register_routes(quart_app: asfquart.base.QuartApp) -> None:
    quart_schema.QuartSchema(
        quart_app,
        openapi_path=None,
        swagger_ui_path=None,
        convert_casing=True,
    )

    quart_app.register_blueprint(API)

def create_app(test_environment: bool = False) -> asfquart.base.QuartApp:
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

    quart_app = asfquart.construct("security-dashboard-api", app_dir, cfg_file, token_file)

    config.setup_app_config(quart_app, app_config)

    _register_routes(quart_app)

    return quart_app
