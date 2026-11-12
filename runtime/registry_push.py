#!/usr/bin/env python3
"""Push a `docker save` archive to a disposable registry with basic auth.

Used only by runtime/staged-acceptance.sh (STAGED_SUITE=registry) inside its
disposable container network, so the operator's Docker daemon and login
settings are never involved. Standard library only.

Usage: registry_push.py ARCHIVE REGISTRY REPOSITORY TAG
Environment: REGISTRY_USER, REGISTRY_PASSWORD
"""
import base64
import hashlib
import json
import os
import sys
import tarfile
import urllib.error
import urllib.parse
import urllib.request


def main():
    archive, registry, repository, tag = sys.argv[1:5]
    token = base64.b64encode(("%s:%s" % (os.environ["REGISTRY_USER"], os.environ["REGISTRY_PASSWORD"])).encode()).decode()
    base = "http://%s/v2/%s" % (registry, repository)

    def call(method, url, data=None, content_type=None):
        headers = {"Authorization": "Basic " + token}
        if content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=data, method=method, headers=headers)
        with urllib.request.urlopen(request, timeout=120) as response:
            return response.status, response.headers

    with tarfile.open(archive) as tar:
        def read(name):
            return tar.extractfile(name).read()

        manifest = json.loads(read("manifest.json"))[0]
        blobs = []

        def upload(data):
            digest = "sha256:" + hashlib.sha256(data).hexdigest()
            status, headers = call("POST", base + "/blobs/uploads/")
            location = urllib.parse.urljoin(base + "/", headers["Location"])
            separator = "&" if "?" in location else "?"
            call("PUT", location + separator + "digest=" + urllib.parse.quote(digest), data, "application/octet-stream")
            return digest, len(data)

        config = read(manifest["Config"])
        config_digest, config_size = upload(config)
        for name in manifest["Layers"]:
            data = read(name)
            media = "application/vnd.oci.image.layer.v1.tar+gzip" if data[:2] == b"\x1f\x8b" else "application/vnd.oci.image.layer.v1.tar"
            digest, size = upload(data)
            blobs.append({"mediaType": media, "digest": digest, "size": size})

    document = {"schemaVersion": 2, "mediaType": "application/vnd.oci.image.manifest.v1+json",
                "config": {"mediaType": "application/vnd.oci.image.config.v1+json", "digest": config_digest, "size": config_size},
                "layers": blobs}
    call("PUT", base + "/manifests/" + tag, json.dumps(document).encode(), "application/vnd.oci.image.manifest.v1+json")
    print("pushed %s/%s:%s with %d layer(s)" % (registry, repository, tag, len(blobs)))


if __name__ == "__main__":
    try:
        main()
    except urllib.error.HTTPError as error:
        sys.exit("registry push failed: HTTP %d %s" % (error.code, error.read()[:200]))
