# Web application and API assessments

Xalgorix builds a previewed, target-bound workflow for web applications and
REST APIs. A preview does not contact the target. Starting the assessment runs
the accepted jobs in dependency order and records stage status, tool output,
and coverage gaps.

## Scope and discovery

Add each approved application URL or host as its own target. A URL target
provides a scheme, host, port, and path boundary. Adding another path, port, or
host requires another explicit target or approved origin; discovery results do
not add scope. Use **Request exclusions** for logout, destructive, purchase,
administrative, or other routes that should never be requested. Enter one rule
per line as `METHOD /path-pattern`, or use `*` for every method, for example:

```text
GET /logout
* /admin/delete*
```

Subdomain enumeration is off by default. When authorized, enable it to run
Subfinder; Amass can be selected as additional passive evidence. Discovered
names remain candidates and are not scanned unless independently in scope.

Historical URL providers (gau, waybackurls) are not part of the workflow, and
a request that sets `discovery_providers.historical` is rejected. TLS
assessment runs testssl.sh for each approved HTTPS hostname and port.

## API definitions

Gray Box and White Box assessments can upload an OpenAPI 3.0/3.1 or Swagger 2.0
definition and bind it to one target. Local JSON references are resolved;
remote references are rejected. The target binding maps operations to that
target's approved origin. Declared API servers are shown in the preview for
review, but they do not authorize additional destinations.

The preview lists each method and path, required parameter locations, request
body media types, security scheme names, and declared servers. Safe GET and
HEAD operations are eligible only when their required inputs are resolved.
Unresolved operations and state-changing methods remain visible with a reason
and are not dispatched. Supplied path and query values are materialized only
for declared OpenAPI parameters; missing values and undeclared inputs remain
visible and block dispatch. Read request-body fixtures can be stored and
referenced, though body-bearing reads are not dispatched. In a declared test
environment, explicit API write approvals can dispatch POST, PUT, PATCH, or
DELETE requests with content-addressed body fixtures where required. Each
approval must match a bound OpenAPI operation and name a cleanup method and
path; POST cleanup must use DELETE, while DELETE cleanup must use PUT with a
restore fixture. Write and cleanup requests use the same target scope and
exclusion checks. The executor records intent before sending and never replays
an approval already in the journal; an uncertain write outcome blocks reruns.

Request-body fixtures can be stored independently of scan configuration with
`POST /api/api-fixtures` using the raw body and its `Content-Type`. The response
contains a flat `ref`, `size_bytes`, and `content_type`; scan configuration
should retain only `ref`. Fixtures are content-addressed, limited to 1 MiB, and
stored with owner-only filesystem permissions. `GET /api/api-fixtures/{ref}`
retrieves a fixture for the authenticated dashboard client and disables caching.
The endpoint does not itself approve or execute an API operation; operation
materialization and write approvals remain separate policy steps. Configure
`write_approvals` in the scan config using `target_id`, `operation_id`, the
OpenAPI `method` and `path`, fixture reference and content type, plus the
cleanup method/path and any required cleanup fixture. Review the scan preview
before starting.

Application credentials are stored in the encrypted credential vault and
bound to targets. For HTTP header or cookie credentials, save the credential
and optionally provide a protected verification URL and response marker. With
neither set, Xalgorix checks the approved target URL and compares authenticated
and anonymous status/redirect behavior; if they look identical, provide a
protected URL or marker. Form login still requires a protected URL and marker.

Form login supports three submission modes. "HTML form post" and "JSON API"
replay the login over HTTP. "Real browser login" drives a headless browser
through the page's own login — suited to single-page apps and NextAuth/Auth.js
logins that need a CSRF round-trip or set their session cookie from a different
endpoint than the form posts to. In browser mode the username/password field
settings are CSS selectors or input names, credentials are only ever entered on
the login page's own origin (cross-origin requests are blocked), and the
captured session cookie is forwarded to the scanners and refreshed on expiry.

The assessment verifies access before authenticated discovery. Credentials are
not sent to archive providers or sibling hosts.

## Coverage and reports

Scan Detail and generated reports distinguish planned jobs from API operation
outcomes. An operation labeled `batch_completed` was added to a scoped ZAP
batch that completed; ZAP does not provide evidence that each seeded operation
was individually exercised. Failed, skipped, and unattempted operations remain
visible. A completed tool process alone is not evidence that every requested
route or assessment type was tested.

The current native API checks cover unauthenticated access to operations that
declare security schemes, credentialed CORS origin reflection, and explicitly
approved, journaled writes with declared cleanup. They do not yet provide
configured authorization expectations, information-disclosure checks, response
content-type or schema validation, or two-identity authorization checks. It also
does not test GraphQL, SOAP, gRPC, WebSockets, broad fuzzing, or inferred
business workflows.
# URL-only Kubernetes exposure checks

Web and API assessments can optionally select the `kube-exposure` scanner when
the target is an explicit HTTP(S) URL. It performs a small, versioned catalog
of same-origin, in-scope GET requests for recognizable Kubernetes Dashboard,
Kubernetes API, Argo CD, Prometheus, and Grafana surfaces. Requests use the
assessment scope, exclusions, redirect policy, rate limiter, and shared request
budget; no credentials are guessed and no state-changing method is sent.

The scanner reports confirmed exposure only when a response predicate proves
unauthenticated access to a sensitive function or data. Product fingerprints
are reported as probable services, while internal service names or namespace
and pod identifiers are information-disclosure observations. Generic 200, 401,
403, ingress error pages, and branding alone are not vulnerabilities.

This is an external black-box observation of a URL. It is not a Kubernetes
cluster audit and cannot inspect Pods, RBAC, Secrets, NetworkPolicies, service
accounts, images, or cluster configuration. Use the separate opt-in
`kube-bench` scanner with operator-supplied cluster access for CIS benchmark
coverage.

# Next.js asset checks

Web and API assessments can optionally select the `nextjs-assets` scanner. It
runs in the passive stage, after the crawl, and reads only JavaScript the
application already serves: script URLs the crawl recorded in the inventory and
`/_next/static/` scripts referenced by the target page. It sends GET requests to
in-scope URLs only, never follows redirects, pins the resolved address of each
origin, uses the shared rate limiter and request budget, and never forwards
credentials. At most 40 scripts are examined; more are recorded as a
`script_limit` limitation.

It reports two things. A Next.js fingerprint (informational) records the
signals seen, the build ID and, when the client runtime exposes it, the
framework version, so the version can be checked against Next.js advisories.
A public source map (low, CWE-540) is reported only when the referenced map
answers HTTP 200 with source-map JSON; inline `data:` maps and HTML fallback
pages are not findings. Only the first 4 KiB of a map is read and its content
is not retained.

Assets are fetched anonymously, recorded as the `anonymous_assets_only`
limitation, so bundles served only to signed-in users are not examined. A
missing version means the served assets did not reveal it, not that the
application is unaffected by an advisory.
