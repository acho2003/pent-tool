# Scanner content lock

`content-lock.json` records candidate image, scanner, and Nuclei template
inputs. The Dockerfile checks the signed Kali `kali-last-snapshot` InRelease
hash before installing packages. When Kali advances that branch, the build
fails until the hash and scanner results are reviewed. The image writes
`/usr/local/share/xalgorix/content-manifest.json` with the binaries actually
present and a digest of its installed Debian package list.

This lock has **not been build-tested** because Docker builds are deferred.
Do not present it as a tested release or claim a quality improvement from the
cached-image baseline. Before releasing an update: review upstream versions and
checksums, build on supported architectures, confirm required scanner commands
and ZAP add-ons, run the lab scorecard repeatedly, then change the lock's
review state and publish measured results. Python and Ruby transitive packages
and the optional Kali tool metapackages still need a fully archived package
repository for bit-for-bit reproducibility. Kali describes
`kali-last-snapshot` as changing at each point release, so the InRelease hash
is an intentional fail-closed check rather than an immutable archive.
