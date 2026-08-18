"""
certificate-api (FastAPI)

Unauthenticated, read-only HTTPS endpoint that serves PUBLIC certificates
stored in HashiCorp Vault (KV v2), without ever exposing a Vault token,
Vault API paths, or private key material to clients.

    GET /certs/<name>.pem  -> raw PEM certificate (application/x-pem-file)
    GET /health            -> {"status": "ok"}

Only GET is registered on these routes, so Starlette/FastAPI returns 405
automatically for POST/PUT/PATCH/DELETE.
"""

import logging
import os
import re
import sys
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse

# --------------------------------------------------------------------------
# Configuration (all from environment — nothing sensitive is hardcoded)
# --------------------------------------------------------------------------

VAULT_ADDR = os.environ.get("VAULT_ADDR", "http://vault:8200").rstrip("/")
VAULT_TOKEN = os.environ.get("VAULT_TOKEN")
VAULT_MOUNT = os.environ.get("VAULT_MOUNT", "certificates")
VAULT_KV_PREFIX = os.environ.get("VAULT_KV_PREFIX", "public")
VAULT_TIMEOUT_SECONDS = float(os.environ.get("VAULT_TIMEOUT_SECONDS", "5"))

if not VAULT_TOKEN:
    # Fail fast at startup rather than serving 502s for every request.
    sys.stderr.write(
        "FATAL: VAULT_TOKEN is not set. Provide it via environment file "
        "or Docker secret, never via source code.\n"
    )
    sys.exit(1)

# Only these characters are allowed in a certificate "name" (the part
# before ".pem"). This intentionally excludes "/" so path traversal
# segments like "../../something" can never be constructed.
CERT_NAME_RE = re.compile(r"^[a-zA-Z0-9._-]+$")

# --------------------------------------------------------------------------
# Logging — deliberately never logs the Vault token or certificate body
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("certificate-api")


# --------------------------------------------------------------------------
# Shared async HTTP client (created once, reused across requests)
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(app: FastAPI):
    app.state.http_client = httpx.AsyncClient(timeout=VAULT_TIMEOUT_SECONDS)
    try:
        yield
    finally:
        await app.state.http_client.aclose()


app = FastAPI(title="certificate-api", docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
# docs_url/redoc_url/openapi_url are disabled deliberately — this API has
# exactly two public routes and doesn't need to advertise a schema.


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def extract_and_validate_cert_name(filename: str):
    """
    Given a raw path segment like 'sso.stg.ebc.edu.kh.pem', return the
    validated certificate name ('sso.stg.ebc.edu.kh') or None if invalid.
    """
    if not filename.endswith(".pem"):
        return None

    name = filename[: -len(".pem")]

    if not name:
        return None

    # Reject traversal explicitly. FastAPI's default {filename} path
    # parameter already can't contain "/" (it only matches a single path
    # segment), but this stays as an explicit, defense-in-depth check.
    if ".." in name or "/" in name or "\\" in name:
        return None

    if not CERT_NAME_RE.match(name):
        return None

    return name


# --------------------------------------------------------------------------
# Vault access
# --------------------------------------------------------------------------

class VaultError(Exception):
    """Raised for any Vault-side failure. Carries an HTTP status to return."""

    def __init__(self, http_status: int, message: str):
        super().__init__(message)
        self.http_status = http_status


async def fetch_certificate_from_vault(client: httpx.AsyncClient, cert_name: str) -> str:
    """
    Reads certificates/data/public/<cert_name> from Vault KV v2 and
    returns the 'certificate' field, verified to look like a PEM cert.
    Raises VaultError with an appropriate status on any failure.
    """
    url = f"{VAULT_ADDR}/v1/{VAULT_MOUNT}/data/{VAULT_KV_PREFIX}/{cert_name}"

    try:
        resp = await client.get(url, headers={"X-Vault-Token": VAULT_TOKEN})
    except httpx.HTTPError as exc:
        log.error("Vault request failed for cert_name=%s: %s", cert_name, type(exc).__name__)
        raise VaultError(502, "Vault is unavailable") from exc

    if resp.status_code == 404:
        raise VaultError(404, "certificate not found")

    if resp.status_code == 403:
        log.error("Vault denied access for cert_name=%s (check policy/token)", cert_name)
        raise VaultError(502, "Vault access denied")

    if resp.status_code != 200:
        log.error(
            "Unexpected Vault status=%s for cert_name=%s", resp.status_code, cert_name
        )
        raise VaultError(502, "Vault returned an unexpected response")

    try:
        payload = resp.json()
        certificate = payload["data"]["data"]["certificate"]
    except (ValueError, KeyError, TypeError):
        log.error("Malformed Vault response structure for cert_name=%s", cert_name)
        raise VaultError(502, "Vault returned malformed data")

    if not isinstance(certificate, str) or not certificate.startswith(
        "-----BEGIN CERTIFICATE-----"
    ):
        log.error("Vault field did not look like a PEM certificate for cert_name=%s", cert_name)
        raise VaultError(502, "Vault returned malformed certificate data")

    return certificate


# --------------------------------------------------------------------------
# Routes
# --------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {"status": "ok"}


@app.get("/certs/{filename}")
async def get_certificate(filename: str):
    cert_name = extract_and_validate_cert_name(filename)
    if cert_name is None:
        log.info("Rejected invalid certificate name request")
        raise HTTPException(status_code=400, detail="invalid certificate name")

    client: httpx.AsyncClient = app.state.http_client
    try:
        pem = await fetch_certificate_from_vault(client, cert_name)
    except VaultError as exc:
        raise HTTPException(status_code=exc.http_status, detail=str(exc)) from exc

    log.info("Served certificate for cert_name=%s", cert_name)
    return Response(
        content=pem,
        media_type="application/x-pem-file",
        headers={"Content-Disposition": f'inline; filename="{cert_name}.pem"'},
    )


# --------------------------------------------------------------------------
# Error shape parity: {"error": "..."} instead of FastAPI's default
# {"detail": "..."} , to match what clients may already expect.
# --------------------------------------------------------------------------

@app.exception_handler(HTTPException)
async def http_exception_handler(_request, exc: HTTPException):
    return JSONResponse(status_code=exc.status_code, content={"error": exc.detail})
