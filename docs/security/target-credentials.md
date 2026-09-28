# Target credential storage

Xalgorix can store target-bound header, cookie, bearer-token, API-key, form-login,
SSH, Windows, cloud, or Kubernetes credential values in its encrypted credential
vault. Credential records live under `<data-dir>/_credentials`; the values are
encrypted with AES-256-GCM, and files/directories are created with owner-only
permissions. API responses return opaque IDs and metadata, never the stored
values.

Set `XALGORIX_CREDENTIAL_KEY_FILE` to a mounted secret containing exactly 32
raw bytes. For example, create one with `openssl rand -out xalgorix-credential.key 32`,
then mount that file read-only into the service. Do not put the key in the scan
data directory, source control, container image, or environment variable value.
Back up the key separately from the encrypted data directory. Losing the key
makes stored credentials unrecoverable. Restoring encrypted credential files
without the matching key also makes them unusable.

To rotate a key, use the vault's `RotateKey` operation while the service is
quiescent, then atomically replace the mounted key file with the same new 32-byte
key before restarting Xalgorix. Keep a protected backup of the previous key and
vault until the rotated records have been verified. The web API does not expose
key rotation.

Credential IDs are associated with assessment target IDs. A lookup for a target
outside that binding fails. The vault is storage only: scanner execution must
still verify credentials and attach them only to the matching target before
running authenticated checks. Typed assessment execution remains unavailable
until that execution path is enabled; use the plan preview endpoint to inspect
scanner decisions.
