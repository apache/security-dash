<!--
 Licensed to the Apache Software Foundation (ASF) under one
 or more contributor license agreements.  See the NOTICE file
 distributed with this work for additional information
 regarding copyright ownership.  The ASF licenses this file
 to you under the Apache License, Version 2.0 (the
 "License"); you may not use this file except in compliance
 with the License.  You may obtain a copy of the License at

   http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing,
 software distributed under the License is distributed on an
 "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 KIND, either express or implied.  See the License for the
 specific language governing permissions and limitations
 under the License.
-->

# Technical documentation

Documentation for the security issue dashboard.

* [`schemas/case.schema.json`](schemas/case.schema.json):
  JSON Schema for the case files that back the dashboard.
* [Input data](#input-data):
  how those files are laid out and what the dashboard reads from them.

## Input data

The dashboard is read-only:
it renders a directory tree of JSON files and never writes to it.
`data_dir` in `config.yaml` points at that tree.

One file is one case: a single reported security issue.
It lists every email linked to that issue —
the original report,
any duplicate reports of the same issue,
and follow-ups that are not part of the same mail thread.
The file **contents** are header metadata only (no message bodies)
and are described by [`schemas/case.schema.json`](schemas/case.schema.json).
The file **path and name** carry the classification,
as described below.

### Directory layout

Every project has a directory named after its PMC:

```
<data_dir>/
  <project>/*.json
```

A case leaves the project directory once it is resolved,
or once it turns out not to be an issue.
It then disappears from the project page,
and stops adding to the project's debt in the statistics
from the date of its last email onwards —
or, if its CVE is listed in `old_cve_close_dates`, from the date given there.

### File names

The name of a case file records how the case was classified.
Free-form text describing the issue is wrapped in optional tokens:

```
[CVE-<id> [CVE-<id> …] | YYYY-MM-DD] [<subproject>] [<issue number>] <free text> [wf <state>].json
```

All of this follows the default process for handling a possible vulnerability,
[documented for committers](https://www.apache.org/security/committers.html#possible).

#### Prefix

Once the case has CVE IDs
([allocated by the security team](https://www.apache.org/security/committers.html#ids)),
the name starts with them —
repeated, when a single case covers more than one.
That also marks the case as confirmed on the project page:
it has been accepted and is being
[resolved](https://www.apache.org/security/committers.html#resolve).

Every other case is named after `YYYY-MM-DD`,
the day its first report came in.
The date is informational:
the dashboard takes the dates it displays from the emails, not from the name.

#### Subproject

For the PMCs listed in `pmcs_with_subprojects`,
the token after the prefix names the subproject the issue belongs to.

#### Issue number

The next token, when it is a number,
is the identifier of the issue tracking the case:
a Jira issue for the PMCs listed in `pmcs_using_jira`,
a GitHub issue for those listed in `pmcs_using_github`.
Such an issue has to be private,
since a public one would disclose the vulnerability —
see [Work in private](https://www.apache.org/security/committers.html#work-in-private).

#### State

A `wf <state>` suffix says what the case is waiting for:

| State                   | Meaning                                                                                                                                     |
|-------------------------|---------------------------------------------------------------------------------------------------------------------------------------------|
| `wf cve-allocation`     | The report has been **accepted**, but no CVE ID has been [allocated](https://www.apache.org/security/committers.html#ids) yet.              |
| `wf non-issue-feedback` | The report has been **rejected**, and the reporter still has to be [told why](https://www.apache.org/security/committers.html#acknowledge). |
| `wf non-issue-docs`     | **Rejected** as a vulnerability, but the documentation should be improved.                                                                  |
| `wf non-issue-upstream` | **Rejected**: the flaw is in an upstream component and has to be fixed, or avoided, there.                                                  |
| `wf disclosure`         | The fix has been released and the [announcement](https://www.apache.org/security/committers.html#announce) still has to go out.             |
| anything else           | Shown as "waiting for …".                                                                                                                   |

A case with neither CVE IDs nor a `wf` suffix is untriaged:
it is waiting for the project team to
[investigate the report and accept or reject it](https://www.apache.org/security/committers.html#acknowledge).

### Contents

Beyond what the schema can express:

* Emails should be ordered oldest first.
  The dashboard takes the first entry as the moment the issue was reported
  and — for a case that has been closed — the last as the moment it was closed.
* An empty array is not an error but has no meaning to the dashboard:
  it is skipped, with a warning on the server log.
* `subj`, `from`, `to`, `cc` and `reply_to` hold raw header values,
  exactly as they appeared in the message.
  They may be RFC 2047 encoded words and are decoded,
  and in the case of the title sanitized,
  before being rendered.
* Only `mailtime`, `subj`, `from`, `to` and `message_id` are required.
  `cc` and `reply_to` are read when a producer supplies them:
  `cc` helps identify the mailing list an email belongs to,
  and `reply_to` recovers the reporter behind a sender rewritten by a list.

### Validating

With [`check-jsonschema`](https://pypi.org/project/check-jsonschema/):

```sh
find "$DATA_DIR" -name '*.json' -print0 |
    xargs -0 uvx check-jsonschema --schemafile docs/schemas/case.schema.json
```
