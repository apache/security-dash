Separate API trigger actions from the dashboard

This API is only for use by the dashboard
and should be restricted on the network level.
Other clients should use the API on the dashboard instead.

Operations are intentionally restrictive to reduce the chance of
invalid/unwanted actions.

This application is assumed to have rw access to the
report data and the capability to send email on behalf
of any @apache.org user.
