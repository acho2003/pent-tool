# Local assessment lab

This lab runs two intentionally vulnerable web applications on different ports
and a fixed counterpart. All published ports bind to `127.0.0.1`. The data and
login credentials are synthetic. Do not expose these containers to a public
interface.

```sh
docker compose -f test/lab/compose.yaml up -d --build --wait
docker compose -f test/lab/compose.yaml down
```

The versioned [manifest](manifest.v1.json) lists expected endpoints and
findings. The endpoints exercise classic crawling, a JavaScript-loaded route,
form login with a hidden CSRF field, an authenticated API route, redirects,
OpenAPI discovery, and separate applications on one hostname. The fixed
counterpart is a negative control. This is a fixture suite, not yet a measured
scanner scorecard: precision and recall gates require actual scanner runs and
normalization of their output against the manifest.

The fixture records requests by path for endpoint coverage and request-count
measurements. Reset counters before each scan and collect them afterward:

```sh
curl -X POST -H 'X-Lab-Control: local-only' http://127.0.0.1:18080/__lab/reset
curl -H 'X-Lab-Control: local-only' http://127.0.0.1:18080/__lab/metrics
```

The control routes are not linked from the fixture pages and are excluded from
the counters. Apply the same calls to ports 18081 and 18082 for the other
applications.

After running an assessment against each application, save its `report.json`
and metrics response. Record one observation per application in a JSON file:

```json
{
  "schema_version": 1,
  "runs": [
    {
      "application_id": "app-a-vulnerable",
      "result_path": "app-a-vulnerable/report.json",
      "metrics_path": "app-a-vulnerable/metrics.json",
      "duration_ms": 12345,
      "peak_memory_bytes": 123456789
    }
  ]
}
```

Include all three application IDs from the manifest. Paths are relative to
the observation file. The duration and peak memory values must come from the
actual run; do not fill in estimates. Generate a machine-readable scorecard:

```sh
go run ./test/lab/scorecard --observations /path/to/observations.json --gate
```

The scorecard counts endpoint requests, true/false positives, false negatives,
precision, recall, and per-class sample sizes. It identifies these five lab
classes by affected path plus the reported CWE or title. Findings without a
matching class or on the fixed application count as false positives. A scan
result without a typed `assessment_coverage` snapshot cannot pass the gate,
even if its scanner process exited successfully. Review the class mapping and
native evidence before publishing a release scorecard; the tool has not yet
run scanners or proven the quality targets.

### Cached-image baseline runner

`run_baseline.py` uses the existing dashboard API to create temporary lab-only
form credentials, preview and run three `web-gentle` assessments, and collect
reports, request counters, wall time, and sampled Docker memory use. It starts
the three lab containers with `--no-build --pull never`; it does not rebuild,
pull, recreate, or restart the running Xalgorix service. The Xalgorix dashboard
must already be running and reachable at `http://127.0.0.1:9137`.

```sh
python3 test/lab/run_baseline.py --output /private/path/xalgorix-baseline-1
go run ./test/lab/scorecard --observations /private/path/xalgorix-baseline-1/observations.json --gate
```

The runner prompts for the dashboard password, or reads it from
`XALGORIX_BENCH_PASSWORD`; `XALGORIX_BENCH_USER` defaults to `admin`. Do not
commit `report.json`, metrics, observations, or the output directory. The
runner deletes each temporary lab credential when its scan ends. It records
the actual running container image IDs, cached image IDs, available tool
versions, and `source_revision: unknown` when the cached image has no
Xalgorix source commit label. A baseline from such an image is useful for
diagnosis but is not a before/after comparison for current source code.

The [2026-10-01 cached-image attempt](baselines/2026-10-01-cached-attempt.json)
records scanner and ZAP content versions, but **no quality measurement**:
the isolated ZAP container first exceeded its memory limit, and the next run
remained queued because the shared Docker server was below Xalgorix's free
memory admission threshold. The existing service was left running. Repeat on
the reference server or with sufficient free memory; do not infer precision or
recall from this attempt.
