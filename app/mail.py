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

import logging
import email
from email.message import EmailMessage
import re
from typing import Final

import aiosmtplib

from app import config

_SMTP_TIMEOUT: Final[int] = 30
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f-\x9f]")
_PMC = re.compile(r"[a-z-]+")
_SENDER = re.compile(r"[a-z]+")

def valid_pmc(pmc):
    """A PMC name ends up in list addresses and report paths, so keep it strict."""
    return _PMC.fullmatch(pmc or "") is not None

def valid_sender(sender):
    """A sender is the local part of an @apache.org address."""
    return _SENDER.fullmatch(sender or "") is not None

def _strip_controls(s):
    return _CONTROL.sub("", (s or "").replace("\r\n", "\n").replace("\r", "\n"))

def _header_value(s):
    """One-line, control-free version of an untrusted header for display/use."""
    return _strip_controls(s or "").replace("\n", " ").strip()

def _response(pmc: str, sender: str, message_id: str, report: dict):
    # the routes check these too, but never build an address out of unchecked input
    if not valid_pmc(pmc):
        raise ValueError(f"Invalid PMC name: {pmc!r}")
    if not valid_sender(sender):
        raise ValueError(f"Invalid sender: {sender!r}")

    res = EmailMessage()
    res["Date"] = email.utils.formatdate()
    res["Message-ID"] = email.utils.make_msgid(domain="dash.security.apache.org")
    res["From"] = f"{sender}@apache.org"
    res["Subject"] = _header_value(f"Re: {report["subj"]}")
    res["To"] = _header_value(report.get("reply_to") or report["from"])

    list_name = config.get().pmc_list_names.get(pmc) or pmc
    if pmc in config.get().pmcs_with_security_emails:
        cc = f"security@{list_name}.apache.org"
    else:
        cc = f"private@{list_name}.apache.org, security@apache.org"
    if report.get("cc"):
        cc = cc + ", " + report["cc"]
    res["Cc"] = _header_value(cc)

    if message_id:
        res["In-Reply-To"] = _header_value(message_id)
        res["References"] = _header_value(message_id)

    return res

def accept_email(acceptance: AcceptReport, report: dict):
    pmc = acceptance.tag.split("/", 1)[0]
    res = _response(pmc, acceptance.sender, acceptance.message_id, report)

    if acceptance.response:
        additional_comment = f"\n{acceptance.response}\n"
    else:
        additional_comment = "";

    res.set_content(f'''Hello,

    Thank you for your report. We have decided to accept it
    and will be working on a fix.
    {additional_comment}
    Please keep this information private. After the version
    with the version with the fix has been released, we will
    publish a CVE advisory crediting you.

    {pmc}
    ''')

    return res

def reject_email(rejection: RejectReport, report: dict):
    pmc = rejection.tag.split("/", 1)[0]
    res = _response(pmc, rejection.sender, rejection.message_id, report)
    if rejection.response:
        additional_comment = f"\n{rejection.response}\n"
    else:
        additional_comment = "";

    res.set_content(f'''Hello,

    Thank you for your report. However, we have decided to reject it.
    {additional_comment}
    {pmc}
    ''')

    return res

async def send_email(email: EmailMessage) -> bool:
    smtp_config = config.get().smtp

    if config.get().dev_mode:
        print(f"[dev] sending email to {email['To']}:\n{email}")
        return True
    else:
        errors, response = await aiosmtplib.send(
            email, hostname=smtp_config.host, port=smtp_config.port, timeout=_SMTP_TIMEOUT, start_tls=True
        )

        if len(errors) == 0:
            print(f"successfully sent email with subject '{email['Subject']}', response = {response}")
            return True
        else:
            print(f"failed to send email with subject '{email['Subject']}', errors = {errors}")
            return False
