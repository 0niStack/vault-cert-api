# certificate-api

Unauthenticated, read-only HTTPS endpoint for fetching **public** certificates
that live in your existing Vault KV v2 mount, without ever exposing a Vault
token, the Vault API, or private keys to clients.

Final result:

```bash
curl -fsSL \
  https://xyz.internal.xyz.com/certs/xzy.stg.internal.com.pem \
  -o xzy.stg.internal.com.pem
```

No Vault token, Vault CLI, Vault account, or Authorization header required.

## Directory structure

```
certificate-api/
├── app.py
├── requirements.txt
├── Dockerfile
├── docker-compose.yml
├── .env.example
├── .gitignore
├── nginx-certs-location.conf
├── vault/
│   └── certificate-api.hcl
└── README.md
```

---

## 1. Vault: create the read-only policy and token

Your Vault container is named `vault` and is already initialized/unsealed —
none of this touches the existing Vault deployment.

**1a. Write the policy into the running container**

```bash
docker exec -i vault sh -c 'cat > /tmp/certificate-api.hcl' <<'EOF'
path "certificates/data/public/*" {
  capabilities = ["read"]
}
EOF
```

**1b. Install the policy**

```bash
docker exec vault vault policy write certificate-api /tmp/certificate-api.hcl
```

Verify:

```bash
docker exec vault vault policy read certificate-api
```

**1c. Create a dedicated token restricted to that policy**

```bash
docker exec vault vault token create \
  -policy="certificate-api" \
  -no-default-policy \
  -orphan \
  -period=768h \
  -display-name="certificate-api-service" \
  -format=json
```

- `-no-default-policy` — the token gets *only* the `certificate-api` policy,
  nothing else.
- `-orphan` — not tied to your personal token's lease.
- `-period=768h` — a renewable (periodic) service token instead of one with
  a hard TTL, so it doesn't expire out from under the API as long as it's
  renewed. Renew periodically with:
  `docker exec vault vault token renew <token>`.

Copy the `.auth.client_token` value out of the JSON output — that's the
value you'll put in `.env` in step 3. Nothing else from that output is
needed.

> **Production note:** if you'll be issuing tokens like this to multiple
> services over time, consider Vault AppRole instead of a long-lived static
> token — same policy, but the API authenticates with a role_id/secret_id
> pair that's easier to rotate. The token approach above satisfies what you
> asked for and is fine for a single internal service.

---

## 2. Docker: find the Vault network and wire up certificate-api

**2a. Discover the network Vault is on**

```bash
docker inspect vault \
  --format '{{range $k, $v := .NetworkSettings.Networks}}{{$k}}{{"\n"}}{{end}}'
```

Take the network name printed here and use it everywhere below marked
`REPLACE_WITH_VAULT_DOCKER_NETWORK_NAME`.

**2b. Fill in docker-compose.yml**

Edit `docker-compose.yml` and replace:

```yaml
networks:
  vault_net:
    external: true
    name: REPLACE_WITH_VAULT_DOCKER_NETWORK_NAME
```

with the real network name from step 2a.

**2c. Create `.env` from the example**

```bash
cp .env.example .env
chmod 600 .env
```

Edit `.env` and set `VAULT_TOKEN` to the token from step 1c. This file is
gitignored and is passed to the container via `env_file:` — the token is
never in `app.py`, the `Dockerfile`, or `docker-compose.yml`.

**2d. Build and start**

```bash
docker compose build
docker compose up -d
```

**2e. If Nginx is also Dockerized and on a different network**

```bash
docker network connect REPLACE_WITH_VAULT_DOCKER_NETWORK_NAME <nginx_container_name>
```

This lets Nginx reach `certificate-api` by service name. If Nginx runs
directly on the host (not in Docker), see the alternative in section 4.

---

## 3. Vault reachability

With `certificate-api` on the same Docker network as `vault`, the app reaches
Vault at `http://vault:8200` — no new Vault port is published, and Vault's
existing auth is untouched (the API just uses its own scoped token like any
other Vault client would).

---

## 4. Nginx: add the `/certs/` location

Add the contents of `nginx-certs-location.conf` inside the **existing**
`server { ... }` block for `vaultx.internal.ebc.edu.kh` — do not replace
anything else in that vhost:

```nginx
location /certs/ {
    proxy_pass http://certificate-api:8080;

    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;

    proxy_connect_timeout 5s;
    proxy_read_timeout 10s;

    limit_except GET {
        deny all;
    }
}
```

Nginx matches the longest plain-prefix location, so `/certs/` will win over
`location /` for any path under `/certs/`, regardless of where it appears in
the file. The one thing to check by hand: if the existing vhost has a
**regex** location (`location ~ ...` or `location ~* ...`), that would take
precedence over this prefix location — make sure none of those match
`/certs/*`.

**If Nginx is NOT on the same Docker network** (e.g. host-installed Nginx,
or a Nginx container that can't join `vault_net`): replace `proxy_pass
http://certificate-api:8080;` with the container's IP on that network:

```bash
docker inspect certificate-api \
  --format '{{range $k, $v := .NetworkSettings.Networks}}{{$v.IPAddress}}{{"\n"}}{{end}}'
```

```nginx
proxy_pass http://<certificate-api-ip>:8080;
```

Note container IPs can change on recreate — the same-network + service-name
approach in section 2e is preferred if at all possible.

**Test and reload:**

```bash
# Host-installed Nginx:
sudo nginx -t
sudo systemctl reload nginx

# Or, if Nginx itself runs in Docker:
docker exec <nginx_container_name> nginx -t
docker exec <nginx_container_name> nginx -s reload
```

---

## 5. Testing, layer by layer

**5a. Vault directly**

```bash
docker exec vault vault kv get \
  -mount=certificates \
  -field=certificate \
  public/xyz.internal.xyz.com
```

**5b. certificate-api health, from inside the Docker network**

```bash
docker run --rm --network REPLACE_WITH_VAULT_DOCKER_NETWORK_NAME curlimages/curl \
  -fsSL http://certificate-api:8080/health
```

**5c. certificate-api certs endpoint, from inside the Docker network**

```bash
docker run --rm --network REPLACE_WITH_VAULT_DOCKER_NETWORK_NAME curlimages/curl \
  -fsSL http://certificate-api:8080/certs/xyz.internal.xyz.com.pem
```

**5d. Through Nginx**

```bash
curl -v https://vaultx.internal.ebc.edu.kh/certs/xyz.internal.xyz.com.pem
```

**5e. Save it (the actual target workflow)**

```bash
curl -fsSL \
  https://vaultx.internal.ebc.edu.kh/certs/xyz.internal.xyz.com.pem \
  -o xyz.internal.xyz.com.pem
```

**5f. Verify it's a valid, correct certificate**

```bash
openssl x509 -in xyz.internal.xyz.com.pem -noout -subject -issuer -dates
```

**5g. Confirm no token is required**

```bash
curl -fsSL https://vaultx.internal.ebc.edu.kh/certs/xyz.internal.xyz.com.pem \
  -o /tmp/check.pem
# No -H "X-Vault-Token: ..." anywhere in that command — success confirms it.
```

---

## 6. Troubleshooting

**404 for a certificate you know exists in Vault**
```bash
# Confirm the exact KV path/field:
docker exec vault vault kv get -mount=certificates public/xyz.internal.xyz.com
# Confirm the URL name matches the KV path segment exactly (case-sensitive).
```

**502 from the API**
```bash
docker logs certificate-api --tail 100
# Common causes: Vault unreachable, token lacks permission, or the
# "certificate" field isn't valid PEM. See the specific checks below.
```

**Docker network failure (certificate-api can't resolve "vault")**
```bash
docker inspect certificate-api --format '{{json .NetworkSettings.Networks}}'
docker inspect vault --format '{{json .NetworkSettings.Networks}}'
# Both should list the same network name. If not, fix docker-compose.yml's
# networks.vault_net.name and re-run `docker compose up -d`.
```

**Vault permission denied (403 in logs)**
```bash
docker exec vault vault policy read certificate-api
docker exec vault vault token capabilities <token> certificates/data/public/xyz.internal.xyz.com
# Should show "read". If not, re-check the policy path matches
# "certificates/data/public/*" exactly (note the "data/" segment required
# by KV v2) and that the token was created with -policy="certificate-api".
```

**Vault container unreachable from certificate-api**
```bash
docker exec certificate-api sh -c "wget -qO- http://vault:8200/v1/sys/health || echo unreachable"
docker ps --filter name=vault
# Confirm the vault container is running and on the same network.
```

**Nginx returning the Vault UI / redirecting instead of hitting the API**
```bash
# Usually means /certs/ isn't matching before another location — check for
# a regex location in the vhost:
grep -n "location" /etc/nginx/sites-enabled/*vaultx* 2>/dev/null
# Or inside a container:
docker exec <nginx_container_name> sh -c "grep -n location /etc/nginx/conf.d/*.conf"
```

**Invalid / malformed PEM returned**
```bash
# Check exactly what Vault has stored, without exposing it in shell history:
docker exec vault vault kv get -mount=certificates -field=certificate \
  public/xyz.internal.xyz.com | head -c 40
# Should start with "-----BEGIN CERTIFICATE-----". If it doesn't, the
# stored value itself needs to be fixed at the source — the API is
# correctly refusing to serve it (502).
```
