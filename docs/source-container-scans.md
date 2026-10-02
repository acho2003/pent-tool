# Source, Dockerfile, SBOM, and image assessments with cached containers

This workflow uses `compose.source.yaml`, which has no Greenbone service, no
Docker socket mount, and no image build definition. It uses the cached
`xalgorix:local` image. Until that image is rebuilt in a later release, its
scanner inventory may differ from this checkout; review the assessment plan
for unavailable tools before interpreting results.

Set an absolute host path. The wrapper rejects relative or missing paths and
blocks image build/pull commands:

```sh
export XALGORIX_SOURCE_DIR="$(pwd)/my-app"
runtime/source-compose.sh config --quiet
runtime/source-compose.sh run --rm --no-deps xalgorix \
  --plan --assessment-mode WHITE_BOX \
  --assessment-type SOURCE_CODE,DEPENDENCIES,INFRASTRUCTURE_AS_CODE \
  --source /workspace/source --artifact-kind filesystem
runtime/source-compose.sh run --rm --no-deps xalgorix \
  --run-assessment --assessment-mode WHITE_BOX \
  --assessment-type SOURCE_CODE,DEPENDENCIES,INFRASTRUCTURE_AS_CODE \
  --source /workspace/source --artifact-kind filesystem
```

The directory is read-only at `/workspace/source`; scan artifacts go to the
separate `source-scan-data` volume at `/data`. The source scan includes the
Dockerfile and supported configuration/dependency manifests. `--plan` reports
which tools can actually run. A Dockerfile scan inspects its text and build
instructions; a container-image assessment checks the built image separately.

For the dashboard and web testing, run
`runtime/source-compose.sh up -d --no-build` and open
`http://127.0.0.1:9138`. Choose **White Box**, **Local source directory**, and
enter `/workspace/source`. Include **Infrastructure as Code** in the requested
coverage for Dockerfile/config checks. The separate ZAP service is available
for web assessments, and neither service depends on Greenbone. A missing
cached image must fail instead of triggering a pull or build.

For an SBOM file already inside the mounted tree, use `--artifact-kind sbom`
with its absolute container path, such as `/workspace/source/sbom.cdx.json`,
and request `DEPENDENCIES` coverage. For an image, use `--artifact-kind image`
with a registry-accessible `name@sha256:<digest>` reference and request
`CONTAINER,DEPENDENCIES` coverage. An image that exists only in the host's
Docker daemon is not available inside Xalgorix; publish it to a registry or
use a separate approved transfer workflow. This configuration does not mount
`/var/run/docker.sock`.

The dashboard generates a temporary password at startup unless a password or
bcrypt hash is set in `.env`. The credential encryption key remains a mounted
secret at `secrets/xalgorix-credential.key`. This workflow does not start,
recreate, or modify the original `docker-compose.yml` stack.
