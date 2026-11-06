# Run the local assessment from the dashboard

Dashboard: http://localhost:9138. Refreshed runtime: 4.5.100-dev.09b74cd. Hard refresh the page after signing in. ZAP uses the tested network add-on 0.28.0. Existing records and credentials are preserved.

The prior assessment combined the native engine, a temporary CLI harness, independent source/network tools, and manual triage. The steps below run the dashboard's supported equivalent. They do not reproduce every CLI follow-up or runtime SBOM reconciliation automatically. The PDF from the operator campaign is still a local file; new dashboard assessments generate their own reports.

## 1. Portal assessment

1. New assessment > Mode & target: GRAY BOX, target http://host.docker.internal:3003, scope Supplied targets only, profile Next.js deep.
2. Coverage: Web application and API. Under Customize optional tools, enable available applicable tools such as ZAP, Nuclei, Dalfox and Wapiti. Automatic selection already includes required tools. Enable Wapiti active fuzzing and choose safe mode; declare the local test environment where prompted. Leave subdomain discovery off.
3. Request exclusions: enter the lines below. These match the operator campaign's broad exclusions.

```
* /*logout*
* /*sign-out*
* /*reset*
* /*revoke*
* /*delete*
* /*remove*
* /*approve*
* /*reject*
* /*export*
* /*download*
* /*/stream/*
```

4. Access & inputs > Target access: bind a Form login to http://host.docker.internal:3003.
   - Login page URL: http://host.docker.internal:3003/sign-in
   - Login is submitted as: JSON API (page script calls an API)
   - Login API URL: http://host.docker.internal:3003/api/auth/login
   - Username/password: use the local test credentials you supplied.
   - Username field: cidNo
   - Password field: password
5. Save encrypted credential. In its saved card set verification URL to http://host.docker.internal:3003/api/auth/session. Test authentication and require a verified result. The login in the operator scan used this JSON endpoint; browser form submission was not used. Keep localhost and host.docker.internal aliases consistent in every field.
6. Review & start: preview the workflow, inspect selected tools and coverage gaps, then start. Leave optional controlled-write/cache/Server Action approval cards empty unless you have the specific disposable fixtures and cleanup paths they require.
7. In the assessment detail, inspect each scanner's terminal, status, completeness, limitations and artifacts. A skipped/failed prerequisite is not a passed test. On completion, Reports > PDF (or the assessment's Report button) downloads that scan's PDF.

## 2. Backend assessments

Run the services as separate assessments, preferably one at a time with this single account. This avoids competing login refreshes and makes coverage easier to inspect.

| Field | Common | CIS |
|---|---|---|
| Target | http://host.docker.internal:5003 | http://host.docker.internal:5016 |
| Verification URL | http://host.docker.internal:5003/common/tat | http://host.docker.internal:5016/cis_service/webauthn/credentials |
| API definition upload | output/dashboard-inputs/common-openapi.json | output/dashboard-inputs/cis-openapi.json |

Use GRAY BOX, Web application + API, Next.js deep, the same optional tools/exclusions and safe Wapiti mode. Upload the matching definition under API definition. Definitions were downloaded from each running service's documentation-json endpoint.

For API authentication select HTTP header or token, header name Authorization, value Bearer <current access token>. Obtain a fresh token from your authenticated app's own API request in browser developer tools (Network > request headers). Enter it only into the encrypted credential field. Bind and verify it on the corresponding API origin. Do not bind the Portal's form login to an API origin: that form login is restricted to its own origin, and the Portal cookie is not automatically forwarded to another port. Header-only tokens cannot automatically refresh using the Portal login; if one expires, renew it and rerun affected jobs. The operator CLI had a custom login/refresh bridge for the APIs.

Review materialized API operations before starting. Supply real disposable path/query values where required; unresolved IDs remain untested. One supplied account does not establish cross-role ownership coverage.

## 3. Source/dependency checks

The scanner container cannot read arbitrary paths on the Mac. The existing source snapshots used by the operator scan remain at:

- /data/full-tools/sources/case-infomation-portal
- /data/full-tools/sources/common_service
- /data/full-tools/sources/cis_service

Create a WHITE BOX assessment, choose Local source directory, and use these container paths (comma-separated). Select Source code, Dependencies and Infrastructure as code where applicable, then inspect the available optional source tools and workflow preview. These are snapshots from the prior campaign, not live mounts of the Mac repositories; fresh source testing requires refreshing the snapshots or mounting the current repositories read-only.

Interpret Portal yarn.lock alerts carefully: the Portal uses Bun and its old Yarn lock is stale. The earlier report's production-runtime advisory filtering came from a separate resolved-dependency SBOM check. A dashboard lockfile alert alone does not demonstrate an affected runtime or exploitable endpoint.

The Next.js deep profile has a 10 requests/second policy, up to 3,000 endpoints and 90 minutes overall. Individual tool, browser and discovery limits can end coverage sooner. The prior operator campaign used smaller time budgets and extra recovery runs; there is no fixed expected scan duration. Evaluate completed coverage and evidence rather than elapsed time alone.
