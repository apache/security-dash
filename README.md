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

# Security issue dashboard

A dashboard over the security issues reported to the Apache Software Foundation,
so that every PMC can see what is still on its plate.

The project page lists the open cases of a project,
grouped by the state they are in —
untriaged, confirmed, waiting for disclosure, and the various kinds of non-issue —
each with a short note on what the PMC is expected to do next.
The statistics page charts the *debt* of a project over the past two years:
the sum, over the issues open at that moment,
of the days since each was reported, plus a constant per issue.

Signing in uses ASF OAuth.
A user sees the projects of the PMCs they belong to;
members of the security team see every project.

## Running

The dashboard needs [uv](https://docs.astral.sh/uv/) and a copy of the issue data.
Copy `config.yaml.example` to `config.yaml`
and point `data_dir` at that data —
see [`docs/`](docs/README.md) for the format it is expected to be in.

```sh
uv run python server.py                   # development: auto-reload and debug
uv run hypercorn server:application       # production
```

## Tests

```sh
uv run --with pytest pytest
```

## Documentation

* [`docs/`](docs/README.md) — the format of the issue data that backs the dashboard.

## License

Apache License, Version 2.0.
