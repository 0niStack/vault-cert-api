"""
certificate-api (FastAPI)

Read-only HTTPS endpoint that serves certificates stored in
HashiCorp Vault KV v2 without exposing Vault tokens or Vault API
paths to clients.

Public certificates:

    GET /certs/<name>.pem

        Vault:
        certificates/public/<name>

Internal certificates:

    GET /internal-certs/<name>.pem

        Vault:
        certificates/internal/<name>

Health:

    GET /health
"""

import asyncio
import logging
import os
import re
import sys
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException, Response
from fastapi.responses import JSONResponse


# --------------------------------------------------------------------------
# Configuration
# --------------------------------------------------------------------------

VAULT_ADDR = os.environ.get(
    "VAULT_ADDR",
    "http://vault:8200",
).rstrip("/")

VAULT_TOKEN = os.environ.get("VAULT_TOKEN")

VAULT_MOUNT = os.environ.get(
    "VAULT_MOUNT",
    "certificates",
)

VAULT_PUBLIC_PREFIX = os.environ.get(
    "VAULT_PUBLIC_PREFIX",
    "public",
)

VAULT_INTERNAL_PREFIX = os.environ.get(
    "VAULT_INTERNAL_PREFIX",
    "internal",
)

VAULT_TIMEOUT_SECONDS = float(
    os.environ.get(
        "VAULT_TIMEOUT_SECONDS",
        "5",
    )
)

VAULT_TOKEN_RENEW_INTERVAL_SECONDS = int(
    os.environ.get(
        "VAULT_TOKEN_RENEW_INTERVAL_SECONDS",
        "14400",
    )
)

VAULT_TOKEN_RENEW_RETRY_SECONDS = int(
    os.environ.get(
        "VAULT_TOKEN_RENEW_RETRY_SECONDS",
        "60",
    )
)


if not VAULT_TOKEN:
    sys.stderr.write(
        "FATAL: VAULT_TOKEN is not set. "
        "Provide it via environment file "
        "or Docker secret, never via source code.\n"
    )
    sys.exit(1)


# Certificate names allowed:
#
# example.com
# harbor.internal.ebc.edu.kh
# root-ca
# internal_ca
#
CERT_NAME_RE = re.compile(
    r"^[a-zA-Z0-9._-]+$"
)


# --------------------------------------------------------------------------
# Logging
# --------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    stream=sys.stdout,
)

log = logging.getLogger(
    "certificate-api"
)


# --------------------------------------------------------------------------
# Vault errors
# --------------------------------------------------------------------------

class VaultError(Exception):
    def __init__(
        self,
        http_status: int,
        message: str,
    ):
        super().__init__(message)
        self.http_status = http_status


# --------------------------------------------------------------------------
# Vault token renewal
# --------------------------------------------------------------------------

async def renew_vault_token_once(
    client: httpx.AsyncClient,
) -> bool:
    """
    Renew the configured Vault token using renew-self.

    Returns True on success.
    """

    url = (
        f"{VAULT_ADDR}"
        "/v1/auth/token/renew-self"
    )

    try:
        resp = await client.post(
            url,
            headers={
                "X-Vault-Token": VAULT_TOKEN,
            },
            json={},
        )

    except httpx.HTTPError as exc:
        log.error(
            "Vault token renewal request failed: %s",
            type(exc).__name__,
        )

        return False

    if resp.status_code != 200:
        log.error(
            "Vault token renewal failed status=%s",
            resp.status_code,
        )

        return False

    try:
        payload = resp.json()

        auth = payload.get("auth") or {}

        lease_duration = auth.get(
            "lease_duration"
        )

        renewable = auth.get(
            "renewable"
        )

        log.info(
            "Vault token renewed successfully "
            "lease_duration=%s renewable=%s",
            lease_duration,
            renewable,
        )

    except ValueError:
        log.info(
            "Vault token renewed successfully"
        )

    return True


async def vault_token_renewal_loop(
    client: httpx.AsyncClient,
):
    """
    Renew immediately at startup, then periodically.

    On failure, retry sooner instead of waiting
    for the normal renewal interval.
    """

    while True:
        try:
            success = (
                await renew_vault_token_once(
                    client
                )
            )

            if success:
                delay = (
                    VAULT_TOKEN_RENEW_INTERVAL_SECONDS
                )
            else:
                delay = (
                    VAULT_TOKEN_RENEW_RETRY_SECONDS
                )

            await asyncio.sleep(delay)

        except asyncio.CancelledError:
            log.info(
                "Vault token renewal task stopped"
            )
            raise

        except Exception:
            log.exception(
                "Unexpected error in Vault "
                "token renewal loop"
            )

            await asyncio.sleep(
                VAULT_TOKEN_RENEW_RETRY_SECONDS
            )


# --------------------------------------------------------------------------
# Application lifecycle
# --------------------------------------------------------------------------

@asynccontextmanager
async def lifespan(
    app: FastAPI,
):
    app.state.http_client = (
        httpx.AsyncClient(
            timeout=VAULT_TIMEOUT_SECONDS
        )
    )

    log.info(
        "Starting certificate-api "
        "vault_addr=%s "
        "mount=%s "
        "public_prefix=%s "
        "internal_prefix=%s "
        "renew_interval=%ss",
        VAULT_ADDR,
        VAULT_MOUNT,
        VAULT_PUBLIC_PREFIX,
        VAULT_INTERNAL_PREFIX,
        VAULT_TOKEN_RENEW_INTERVAL_SECONDS,
    )

    renewal_task = asyncio.create_task(
        vault_token_renewal_loop(
            app.state.http_client
        )
    )

    app.state.vault_renewal_task = (
        renewal_task
    )

    try:
        yield

    finally:
        renewal_task.cancel()

        try:
            await renewal_task

        except asyncio.CancelledError:
            pass

        await (
            app.state.http_client.aclose()
        )

        log.info(
            "certificate-api stopped"
        )


# --------------------------------------------------------------------------
# FastAPI application
# --------------------------------------------------------------------------

app = FastAPI(
    title="certificate-api",
    docs_url=None,
    redoc_url=None,
    openapi_url=None,
    lifespan=lifespan,
)


# --------------------------------------------------------------------------
# Validation
# --------------------------------------------------------------------------

def extract_and_validate_cert_name(
    filename: str,
):
    """
    Convert:

        harbor.internal.ebc.edu.kh.pem

    into:

        harbor.internal.ebc.edu.kh

    Reject path traversal and invalid characters.
    """

    if not filename.endswith(".pem"):
        return None

    name = filename[
        :-len(".pem")
    ]

    if not name:
        return None

    if (
        ".." in name
        or "/" in name
        or "\\" in name
    ):
        return None

    if not CERT_NAME_RE.fullmatch(
        name
    ):
        return None

    return name


# --------------------------------------------------------------------------
# Vault certificate access
# --------------------------------------------------------------------------

async def fetch_certificate_from_vault(
    client: httpx.AsyncClient,
    cert_name: str,
    prefix: str,
) -> str:
    """
    Read a certificate from Vault KV v2.

    Example public path:

        certificates/public/example.com

    Vault API path:

        /v1/certificates/data/public/example.com


    Example internal path:

        certificates/internal/harbor.internal.ebc.edu.kh

    Vault API path:

        /v1/certificates/data/internal/harbor.internal.ebc.edu.kh
    """

    url = (
        f"{VAULT_ADDR}"
        f"/v1/{VAULT_MOUNT}"
        f"/data/{prefix}"
        f"/{cert_name}"
    )

    try:
        resp = await client.get(
            url,
            headers={
                "X-Vault-Token":
                    VAULT_TOKEN,
            },
        )

    except httpx.HTTPError as exc:
        log.error(
            "Vault request failed "
            "prefix=%s "
            "cert_name=%s: %s",
            prefix,
            cert_name,
            type(exc).__name__,
        )

        raise VaultError(
            502,
            "Vault is unavailable",
        ) from exc


    # --------------------------------------------------------------
    # Certificate does not exist
    # --------------------------------------------------------------

    if resp.status_code == 404:
        raise VaultError(
            404,
            "certificate not found",
        )


    # --------------------------------------------------------------
    # Vault policy denied access
    # --------------------------------------------------------------

    if resp.status_code == 403:
        log.error(
            "Vault denied access "
            "prefix=%s "
            "cert_name=%s "
            "(check policy/token)",
            prefix,
            cert_name,
        )

        raise VaultError(
            502,
            "Vault access denied",
        )


    # --------------------------------------------------------------
    # Unexpected Vault response
    # --------------------------------------------------------------

    if resp.status_code != 200:
        log.error(
            "Unexpected Vault status=%s "
            "prefix=%s "
            "cert_name=%s",
            resp.status_code,
            prefix,
            cert_name,
        )

        raise VaultError(
            502,
            "Vault returned an "
            "unexpected response",
        )


    # --------------------------------------------------------------
    # Parse Vault KV v2 response
    # --------------------------------------------------------------

    try:
        payload = resp.json()

        certificate = (
            payload["data"]
            ["data"]
            ["certificate"]
        )

    except (
        ValueError,
        KeyError,
        TypeError,
    ) as exc:

        log.error(
            "Malformed Vault response "
            "structure "
            "prefix=%s "
            "cert_name=%s",
            prefix,
            cert_name,
        )

        raise VaultError(
            502,
            "Vault returned malformed data",
        ) from exc


    # --------------------------------------------------------------
    # Make sure Vault returned a certificate,
    # not a private key or arbitrary secret
    # --------------------------------------------------------------

    if (
        not isinstance(
            certificate,
            str,
        )
        or not certificate.startswith(
            "-----BEGIN CERTIFICATE-----"
        )
    ):
        log.error(
            "Vault field did not look like "
            "a PEM certificate "
            "prefix=%s "
            "cert_name=%s",
            prefix,
            cert_name,
        )

        raise VaultError(
            502,
            "Vault returned malformed "
            "certificate data",
        )

    return certificate


# --------------------------------------------------------------------------
# Health
# --------------------------------------------------------------------------

@app.get("/health")
async def health():
    return {
        "status": "ok",
    }


# --------------------------------------------------------------------------
# Public certificates
#
# URL:
#
#   /certs/sso.stg.ebc.edu.kh.pem
#
# Vault:
#
#   certificates/public/sso.stg.ebc.edu.kh
# --------------------------------------------------------------------------

@app.get("/certs/{filename}")
async def get_public_certificate(
    filename: str,
):

    cert_name = (
        extract_and_validate_cert_name(
            filename
        )
    )

    if cert_name is None:
        log.info(
            "Rejected invalid public "
            "certificate name request"
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "invalid certificate name"
            ),
        )


    client: httpx.AsyncClient = (
        app.state.http_client
    )

    try:
        pem = (
            await fetch_certificate_from_vault(
                client,
                cert_name,
                VAULT_PUBLIC_PREFIX,
            )
        )

    except VaultError as exc:
        raise HTTPException(
            status_code=exc.http_status,
            detail=str(exc),
        ) from exc


    log.info(
        "Served public certificate "
        "cert_name=%s",
        cert_name,
    )


    return Response(
        content=pem,
        media_type=(
            "application/x-pem-file"
        ),
        headers={
            "Content-Disposition":
                (
                    f'inline; '
                    f'filename="{cert_name}.pem"'
                )
        },
    )


# --------------------------------------------------------------------------
# Internal certificates
#
# URL:
#
#   /internal-certs/harbor.internal.ebc.edu.kh.pem
#
# Vault:
#
#   certificates/internal/harbor.internal.ebc.edu.kh
# --------------------------------------------------------------------------

@app.get(
    "/internal-certs/{filename}"
)
async def get_internal_certificate(
    filename: str,
):

    cert_name = (
        extract_and_validate_cert_name(
            filename
        )
    )

    if cert_name is None:
        log.info(
            "Rejected invalid internal "
            "certificate name request"
        )

        raise HTTPException(
            status_code=400,
            detail=(
                "invalid certificate name"
            ),
        )


    client: httpx.AsyncClient = (
        app.state.http_client
    )

    try:
        pem = (
            await fetch_certificate_from_vault(
                client,
                cert_name,
                VAULT_INTERNAL_PREFIX,
            )
        )

    except VaultError as exc:
        raise HTTPException(
            status_code=exc.http_status,
            detail=str(exc),
        ) from exc


    log.info(
        "Served internal certificate "
        "cert_name=%s",
        cert_name,
    )


    return Response(
        content=pem,
        media_type=(
            "application/x-pem-file"
        ),
        headers={
            "Content-Disposition":
                (
                    f'inline; '
                    f'filename="{cert_name}.pem"'
                )
        },
    )


# --------------------------------------------------------------------------
# Error format
# --------------------------------------------------------------------------

@app.exception_handler(
    HTTPException
)
async def http_exception_handler(
    _request,
    exc: HTTPException,
):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
        },
    )
