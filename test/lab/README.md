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
