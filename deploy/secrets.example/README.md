# Production secrets (Docker secrets)

Copy this directory to `deploy/secrets/` and replace every placeholder with a
real value, then run:

    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d

Files map to Docker secrets mounted at `/run/secrets/<name>` and read by the app
via the `*_FILE` convention. The real `deploy/secrets/` directory is gitignored.

- `api_keys.json`                — FURIX_API_KEYS_FILE (JSON list of {key,key_id,tenant,role})
- `session_secret.txt`          — BFF sealed-session key (32+ random bytes)
- `mint_secret.txt`             — shared: BFF mints, API verifies (must match)
- `connector_signing_secret.txt`— connector manifest HMAC signing secret
- `attest_keys.json`            — attestation signing key ring
- `bff_users.json`              — BFF user directory (sha256 password hashes)
- `oidc_client_secret.txt`      — OIDC client secret (omit for public/PKCE clients)
