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

from app import config
import dataclasses
import datetime
from email.header import decode_header
from email.utils import getaddresses
from enum import Enum, auto
import hashlib
import json
import pathlib
from quart import current_app
import re

GLASSWING_LABEL = "aaa-glasswing"
"""Label holding the CVEs allocated as part of the Glasswing audit, rather
   than reported separately from outside."""

NOT_FORWARDED_LABEL = "aaa-non-fwd"
"""Label collecting the threads that have not been forwarded to the PMC yet."""

GLASSWING_STATE = "glasswing"
NOT_FORWARDED_STATE = "non-fwd"

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}")
_CVE_PUBLISHED_SUFFIX = "was pushed to cve.org"
"""Subject suffix of the mail announcing that a CVE went public."""

@dataclasses.dataclass(frozen=True)
class Reporter:
    name: str
    email: str

    @property
    def display_name(self) -> str:
        return self.name or self.email or "unknown"

    @property
    def tooltip(self) -> str:
        if self.name and self.email:
            return f"{self.name} <{self.email}>"
        return self.email or self.name or "unknown"

    @property
    def initials(self) -> str:
        source = self.name or self.email.split('@', 1)[0]
        letters = [w[0] for w in re.split(r'\s+', source) if w]
        if not letters:
            return '?'
        return ''.join(letters[:3]).upper()

    @property
    def color(self) -> str:
        digest = hashlib.md5(self.email.lower().encode()).hexdigest()
        hue = int(digest[:4], 16) % 360
        return f"hsl({hue}, 55%, 45%)"

@dataclasses.dataclass(frozen=True)
class ThreadLink:
    """A mailing list thread that was merged into a report, other than
       the thread the report is primarily about."""
    title: str
    link: str

@dataclasses.dataclass(frozen=True)
class Report:
    security_team_name: str
    """internal label the security team assigned to the thread,
       this is not a secret but not meant for external communication"""
    cves: list[str]
    github: (str, str)
    """If this project tracks security issues in private GitHub issues, the GitHub issue link (title and url)"""
    jira: str
    """If this project tracks security issues in private jira issues, the Jira ID"""
    title: str
    message_id: str
    """message_id of the first email in the thread."""
    listid: str
    """list id of the first email in the thread."""
    link: str
    """link to the email archive for project members who may not
       necessarily be ASF members."""
    reporter: Reporter | None

    state: str

    subproject: str | None
    """For PMCs split across subprojects, the subproject this report belongs to."""

    timestamp: datetime.datetime
    duplicates: tuple[ThreadLink, ...] = ()
    """Other threads collapsed into this report, earliest first."""

    @property
    def date(self) -> datetime.date:
        return self.timestamp.date()

    @property
    def sanitized_title(self) -> str:
        cleaned = re.sub(r"[^A-Za-z0-9 .\-()]", " ", self.title)
        cleaned = re.sub(r"\s+", " ", cleaned).strip()
        return cleaned[:200]

    @property
    def asf_member_link(self) -> str:
        return _ponymail_link(self.message_id, self.listid)

def _known_bad_address(time: str | None, address: str):
    if time:
        mailtime = datetime.datetime.fromtimestamp(time, tz=datetime.timezone.utc).date()
        spark_retirement = datetime.date.fromisoformat("2026-02-16")
        if address == 'security@spark.apache.org' and spark_retirement < mailtime:
            return True
    return False

def _apache_list_address(email):
    addresses = list(getaddresses([email['to']]))
    if 'cc' in email:
        addresses.extend(getaddresses([email['cc']]))
    for _, address in addresses:
        if address == "officesecurity@lists.freedesktop.org":
            return "security@openoffice.apache.org"
        if address.endswith('.apache.org') and not _known_bad_address(email.get('mailtime'), address):
            return address
    return None

def _ponymail_link(message_id, listid):
    partly_encoded_message_id = message_id.replace(' ', '+').replace('+', '%2B').replace('=', '%3D').replace('@', '%40')
    return f"https://lists.apache.org/thread/{partly_encoded_message_id}?<{listid}>"

def _project_link(emails):
    for email in emails[:5]:
        list_addr = _apache_list_address(email)
        if list_addr:
            return _ponymail_link(email['message_id'], list_addr.replace('@', '.'))
    return _ponymail_link(emails[0]['message_id'], "security.apache.org")

def _safe_link(emails):
    """link that is likely correct even if the PMC is failing to moderate some emails"""
    email = emails[0]
    addresses = list(getaddresses([email['to']]))
    if 'cc' in email:
        addresses.extend(getaddresses([email['cc']]))
    for _, address in addresses:
        if address.startswith("security") and address.endswith(".apache.org"):
            return _ponymail_link(emails[0]['message_id'], "security.apache.org")
    return _project_link(emails)

def _subject(email) -> str:
    raw_subject = email.get('subj', '')
    try:
        subject = "".join(
            s.decode(c or "ascii", errors="replace") if isinstance(s, bytes) else s
            for s, c in decode_header(raw_subject)
        )
    except Exception:
        subject = raw_subject
    return subject.strip()

def _title(email) -> str:
    title = _subject(email) or "(untitled)"
    if title.startswith("[SECURITY] "):
        title = title.removeprefix("[SECURITY] ")
    elif title.startswith("[Security] "):
        title = title.removeprefix("[Security] ")
    return title

def _threads(emails, link_fn) -> list[ThreadLink]:
    """One entry per distinct thread in the report, earliest first."""
    groups: dict[str, list] = {}
    for email in emails:
        groups.setdefault(_thread_key(_title(email)), []).append(email)
    return [
        ThreadLink(_title(group[0]), link_fn(group))
        for group in groups.values()
    ]

def _reporter(email) -> Reporter | None:
    addresses = [a for a in getaddresses([email.get('from', '')]) if a[1]]
    if not addresses:
        return None
    name, address = addresses[0]
    if ' via ' in name and address.endswith('apache.org'):
        reply_to_addresses = [a for a in getaddresses([email.get('reply_to', '')]) if a[1]]
        if not reply_to_addresses:
            return None
        name, address = reply_to_addresses[0]
    return Reporter(name=name, email=address)

def load_pmc_report(pmc: str, path: pathlib.Path) -> Report | None:
    with open(path) as f:
        emails = json.loads(f.read())

    m = re.match(r"(?:CVE-\S+\s+)*CVE-\S+", path.name)
    cves = m.group(0).split() if m else []

    return _load_pmc_report(pmc, path.name[:-5], cves, emails)

def _load_pmc_report(pmc: str, name: str, cves: list[str], emails: list[object]) -> Report | None:
    jira = None
    if pmc in config.get().pmcs_using_jira:
        m = re.match(r"\S+ (\d+) .*", name)
        if m:
            jira = config.get().pmcs_using_jira[pmc] + "-" + m.group(1)

    github = None
    if pmc in config.get().pmcs_using_github:
        for email in emails:
            m = re.match(r"^\[.*#(\d+)\)$", email['subj'])
            if m:
                issue_nr = m.group(1)
                github = (f"#{issue_nr}", f"https://github.com/{config.get().pmcs_using_github[pmc]}/issues/{issue_nr}")
                break

    if cves:
        state = "confirmed"
    else:
        m = re.match(r".*wf (.*)", name)
        if not m:
            state = "untriaged"
        elif m.groups()[0] == "cve-allocation":
            state = "confirmed"
        else:
            state = m.groups()[0]

    # the subproject is the word after the leading date or CVE(s)
    m = re.match(r"(?:(?:CVE-\S+\s+)*CVE-\S+|\d{4}-\d{2}-\d{2})\s+(\w+)", name)
    subproject = m.group(1) if m else None

    if not emails:
        print(f"Empty label: {name}")
        return None

    first_email = emails[0]
    title = _title(first_email)

    apache_list_address = _apache_list_address(first_email)
    if apache_list_address:
        listid = apache_list_address.replace('@', '.')
    else:
        listid = 'security.apache.org'

    if pmc in config.get().pmcs_with_failing_moderation:
        link_fn = _safe_link
    else:
        link_fn = _project_link

    link = link_fn(emails)
    duplicates = tuple(t for t in _threads(emails, link_fn)[1:] if t.link != link)

    return Report(
        name,
        cves,
        github,
        jira,
        title,
        first_email['message_id'],
        listid,
        link,
        _reporter(first_email),
        state,
        subproject,
        datetime.datetime.fromtimestamp(first_email['mailtime'], tz=datetime.timezone.utc),
        duplicates=duplicates,
    )

def _read_emails(path: pathlib.Path) -> list[object]:
    try:
        with open(path) as f:
            emails = json.loads(f.read())
    except (OSError, ValueError):
        print(f"Unreadable label: {path.name}")
        return []
    # these labels collect many threads, so tolerate the odd unusable mail
    return [
        e for e in emails
        if isinstance(e, dict) and e.get('message_id') and e.get('mailtime')
    ]

def _label_report(name: str, cves: list[str], email, state: str) -> Report:
    """A report that stands for one entry inside a multi-thread label."""
    apache_list_address = _apache_list_address(email)
    if apache_list_address:
        listid = apache_list_address.replace('@', '.')
    else:
        listid = 'security.apache.org'

    return Report(
        name,
        cves,
        None,
        None,
        _title(email),
        email['message_id'],
        listid,
        _project_link([email]),
        _reporter(email),
        state,
        None,
        datetime.datetime.fromtimestamp(email['mailtime'], tz=datetime.timezone.utc),
    )

def _load_glasswing_reports(path: pathlib.Path) -> list[Report]:
    """One entry per CVE allocated under the audit label but not published yet.

    A CVE counts as published once the label holds the mail announcing it was
    pushed to cve.org; until then it is listed with the mail that allocated it.
    """
    allocated: dict[str, object] = {}
    published: set[str] = set()

    for email in _read_emails(path):
        subject = _subject(email)
        cves = _CVE_RE.findall(subject)
        if not cves:
            continue
        if subject.lower().endswith(_CVE_PUBLISHED_SUFFIX):
            published.update(cves)
            continue
        for cve in cves:
            allocated.setdefault(cve, email)

    return [
        _label_report(path.name, [cve], email, GLASSWING_STATE)
        for cve, email in allocated.items()
        if cve not in published
    ]

# a reply prefix, in the languages reporters actually use, or a [SECURITY] tag
_SUBJECT_PREFIX_RE = re.compile(
    r"^\s*(?:(?:re|aw|antw|fw|fwd|sv|vs)\s*(?:\[\d+\])?\s*:|\[security\])\s*",
    re.IGNORECASE,
)

def _thread_key(subject: str) -> str:
    """Group a thread's mails together by their subject, minus any prefixes."""
    while True:
        stripped = _SUBJECT_PREFIX_RE.sub("", subject)
        if stripped == subject:
            break
        subject = stripped
    return re.sub(r"\s+", " ", subject).strip().lower()

def _load_not_forwarded_reports(path: pathlib.Path) -> list[Report]:
    """One entry per thread head under the not-forwarded label."""
    heads: dict[str, object] = {}

    for email in _read_emails(path):
        key = _thread_key(_subject(email))
        head = heads.get(key)
        if head is None or email['mailtime'] < head['mailtime']:
            heads[key] = email

    return [
        _label_report(path.name, [], email, NOT_FORWARDED_STATE)
        for email in heads.values()
    ]

_LABEL_LOADERS = {
    GLASSWING_LABEL: _load_glasswing_reports,
    NOT_FORWARDED_LABEL: _load_not_forwarded_reports,
}

MULTI_THREAD_LABELS = frozenset(_LABEL_LOADERS)
"""Labels that hold many threads instead of a single report."""

def _load_reports_dir(pmc: str) -> list[Report]:
    d = config.get().data_dir_path / pmc
    threads = list(d.glob('**/*.json'))

    result: list[Report] = []
    for t in threads:
        # a handful of labels hold many threads instead of a single report
        loader = _LABEL_LOADERS.get(t.stem)
        if loader:
            result.extend(loader(t))
            continue
        r = load_pmc_report(pmc, t)
        if r is not None:
            result.append(r)
    return result

async def load_pmc_reports(pmc: str) -> list[Report]:
    if not re.fullmatch(r"[a-z0-9]+", pmc):
        raise ValueError(f"invalid PMC name: {pmc!r}")

    result = _load_reports_dir(pmc)
    # attic projects no longer have a PMC, so the security team
    # handles their reports directly
    if pmc == "security":
        for attic_pmc in config.get().pmcs_in_attic:
            if not re.fullmatch(r"[a-z0-9]+", attic_pmc):
                continue
            result.extend(
                dataclasses.replace(r, subproject=attic_pmc)
                for r in _load_reports_dir(attic_pmc)
            )
    return result
