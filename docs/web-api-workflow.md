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

Historical discovery is also opt-in because it contacts public archive
providers. Select either gau or waybackurls. Archived URLs are candidates,
query values are discarded, and eligible paths are revalidated before use.
TLS assessment selects one provider for each approved HTTPS hostname and port;
the default is testssl.sh, with SSLyze available as an alternative.

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
visible and block dispatch. Request-body fixtures can be stored and referenced,
but body-bearing reads and write execution remain unavailable until their
dedicated policy stages are complete. POST approvals must name a cleanup method,
path, and fixture; the cleanup destination is checked against the same scope and
exclusions as the write request.

Request-body fixtures can be stored independently of scan configuration with
`POST /api/api-fixtures` using the raw body and its `Content-Type`. The response
contains a flat `ref`, `size_bytes`, and `content_type`; scan configuration
should retain only `ref`. Fixtures are content-addressed, limited to 1 MiB, and
stored with owner-only filesystem permissions. `GET /api/api-fixtures/{ref}`
retrieves a fixture for the authenticated dashboard client and disables caching.
The endpoint does not itself approve or execute an API operation; operation
materialization and write approvals remain separate policy steps.

Application credentials are stored in the encrypted credential vault and
bound to targets. For authenticated work, configure a protected verification
URL and a response marker; the assessment verifies access before authenticated
discovery. Credentials are not sent to archive providers or sibling hosts.

## Coverage and reports

Scan Detail and generated reports distinguish planned jobs from API operation
outcomes. An operation labeled `batch_completed` was added to a scoped ZAP
batch that completed; ZAP does not provide evidence that each seeded operation
was individually exercised. Failed, skipped, and unattempted operations remain
visible. A completed tool process alone is not evidence that every requested
route or assessment type was tested.

The current native API checks cover only unauthenticated access to operations
that declare security schemes and credentialed CORS origin reflection. They do
not yet provide operation-specific request fixtures, configured authorization
expectations, information-disclosure checks, response content-type or schema
validation, approved write workflows, or two-identity authorization checks. It
also does not test GraphQL, SOAP, gRPC, WebSockets, broad fuzzing, or inferred
business workflows.
