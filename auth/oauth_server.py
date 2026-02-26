from __future__ import annotations

import base64
import binascii
import secrets
import time

from starlette.requests import Request
from starlette.responses import JSONResponse, RedirectResponse, Response

from auth import signed_token, x_oauth2
from auth.client_registry import ClientRegistry
from auth.cors import (
    DEFAULT_CORS_ORIGINS,
    apply_cors_response,
    cors_error_response,
    mount_preflight_route,
)
from auth.models import PendingAuth, PendingCode
from auth.urls import append_query_params, is_allowed_redirect_uri

DEFAULT_SCOPES = ["tweet.read", "tweet.write", "users.read", "offline.access"]


class OAuthServer:
    def __init__(
        self,
        *,
        public_url: str,
        x_client_id: str,
        x_client_secret: str,
        client_registry: ClientRegistry,
        scopes: list[str] | None = None,
        cors_origins: set[str] | None = None,
        pending_auth_ttl_seconds: int = 600,
        pending_code_ttl_seconds: int = 60,
        allowed_user_id: str | None = None,
        exchange_code_fn=x_oauth2.exchange_code,
        refresh_token_fn=x_oauth2.refresh_token,
        fetch_user_id_fn=x_oauth2.fetch_user_id,
    ) -> None:
        self.public_url = public_url.rstrip("/")
        self.x_client_id = x_client_id
        self.x_client_secret = x_client_secret
        self.client_registry = client_registry
        self.scopes = scopes or list(DEFAULT_SCOPES)
        self.cors_origins = set(DEFAULT_CORS_ORIGINS)
        if cors_origins:
            self.cors_origins.update(cors_origins)

        self.pending_auth_ttl_seconds = pending_auth_ttl_seconds
        self.pending_code_ttl_seconds = pending_code_ttl_seconds
        self.allowed_user_id = allowed_user_id

        self.pending_auth: dict[str, PendingAuth] = {}
        self.pending_codes: dict[str, PendingCode] = {}

        self._session_key = signed_token.derive_key(x_client_secret)
        self._exchange_code_fn = exchange_code_fn
        self._refresh_token_fn = refresh_token_fn
        self._fetch_user_id_fn = fetch_user_id_fn

    # -- session token helpers -------------------------------------------------

    def _mint_session_tokens(
        self,
        *,
        x_access_token: str,
        x_refresh_token: str,
        x_expires_at: float,
        client_id: str,
    ) -> tuple[str, str]:
        now = time.time()
        base = {
            "xat": x_access_token,
            "xrt": x_refresh_token,
            "xexp": x_expires_at,
            "cid": client_id,
            "iat": now,
        }
        access = signed_token.encode({**base, "typ": "a"}, self._session_key)
        refresh = signed_token.encode({**base, "typ": "r"}, self._session_key)
        return access, refresh

    def decode_session_token(self, token: str) -> dict:
        return signed_token.decode(token, self._session_key)

    async def resolve_x_access_token(self, session_access_token: str) -> str:
        payload = self.decode_session_token(session_access_token)
        if payload.get("xexp", 0) <= time.time():
            raise RuntimeError(
                "X access token expired; session refresh required."
            )
        return payload["xat"]

    # -- routes ----------------------------------------------------------------

    def metadata_payload(self) -> dict:
        return {
            "issuer": self.public_url,
            "authorization_endpoint": f"{self.public_url}/authorize",
            "token_endpoint": f"{self.public_url}/token",
            "registration_endpoint": f"{self.public_url}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "token_endpoint_auth_methods_supported": [
                "client_secret_basic",
                "client_secret_post",
            ],
            "code_challenge_methods_supported": ["S256"],
            "scopes_supported": self.scopes,
        }

    def mount_routes(self, mcp) -> None:
        @mcp.custom_route("/.well-known/oauth-authorization-server", methods=["GET"])
        async def metadata_route(request: Request) -> Response:
            return apply_cors_response(
                request,
                JSONResponse(self.metadata_payload()),
                self.cors_origins,
            )

        @mcp.custom_route("/register", methods=["POST"])
        async def register_route(request: Request) -> Response:
            return await self._handle_register(request)

        @mcp.custom_route("/authorize", methods=["GET"])
        async def authorize_route(request: Request) -> Response:
            return await self._handle_authorize(request)

        @mcp.custom_route("/x/callback", methods=["GET"])
        async def x_callback_route(request: Request) -> Response:
            return await self._handle_x_callback(request)

        @mcp.custom_route("/token", methods=["POST"])
        async def token_route(request: Request) -> Response:
            return await self._handle_token(request)

        paths = (
            "/.well-known/oauth-authorization-server",
            "/register",
            "/authorize",
            "/x/callback",
            "/token",
        )
        for path in paths:
            mount_preflight_route(mcp, path, self.cors_origins)

    # -- handlers --------------------------------------------------------------

    async def _handle_register(self, request: Request) -> Response:
        try:
            payload = await request.json()
        except Exception:
            return self._error(request, "invalid_request", "Invalid JSON body.", 400)

        client_name = payload.get("client_name")
        redirect_uris = payload.get("redirect_uris")

        if not isinstance(client_name, str) or not client_name.strip():
            return self._error(request, "invalid_client_metadata", "client_name is required.", 400)
        if not isinstance(redirect_uris, list) or not redirect_uris:
            return self._error(
                request,
                "invalid_redirect_uri",
                "redirect_uris is required.",
                400,
            )
        if not all(isinstance(uri, str) for uri in redirect_uris):
            return self._error(
                request,
                "invalid_redirect_uri",
                "redirect_uris must contain strings.",
                400,
            )
        if not all(is_allowed_redirect_uri(uri) for uri in redirect_uris):
            return self._error(
                request,
                "invalid_redirect_uri",
                "One or more redirect_uris are not allowed.",
                400,
            )

        client = self.client_registry.register(client_name=client_name, redirect_uris=redirect_uris)
        return apply_cors_response(
            request,
            JSONResponse(
                {
                    "client_id": client.client_id,
                    "client_secret": client.client_secret,
                    "client_name": client.client_name,
                    "redirect_uris": client.redirect_uris,
                },
                status_code=201,
            ),
            self.cors_origins,
        )

    async def _handle_authorize(self, request: Request) -> Response:
        self._cleanup_pending_auth()

        client_id = request.query_params.get("client_id")
        redirect_uri = request.query_params.get("redirect_uri")
        code_challenge = request.query_params.get("code_challenge")
        code_challenge_method = request.query_params.get("code_challenge_method")
        state = request.query_params.get("state")

        if not client_id or not redirect_uri or not code_challenge or not state:
            return self._error(
                request, "invalid_request", "Missing required query parameters.", 400
            )

        if code_challenge_method != "S256":
            return self._error(
                request, "invalid_request", "code_challenge_method must be S256.", 400
            )

        client = self.client_registry.get(client_id)
        if client is None:
            return self._error(request, "invalid_client", "Unknown client_id.", 400)

        if redirect_uri not in client.redirect_uris:
            return self._error(request, "invalid_redirect_uri", "Invalid redirect_uri.", 400)

        x_state = secrets.token_urlsafe(24)
        x_code_verifier = x_oauth2.generate_code_verifier()
        x_code_challenge = x_oauth2.generate_code_challenge(x_code_verifier)

        self.pending_auth[x_state] = PendingAuth(
            client_id=client_id,
            redirect_uri=redirect_uri,
            code_challenge=code_challenge,
            original_state=state,
            x_code_verifier=x_code_verifier,
            created_at=time.time(),
        )

        x_authorize_url = x_oauth2.build_authorization_url(
            client_id=self.x_client_id,
            redirect_uri=f"{self.public_url}/x/callback",
            scopes=self.scopes,
            state=x_state,
            code_challenge=x_code_challenge,
        )

        return apply_cors_response(
            request,
            RedirectResponse(url=x_authorize_url, status_code=302),
            self.cors_origins,
        )

    async def _handle_x_callback(self, request: Request) -> Response:
        self._cleanup_pending_auth()

        if request.query_params.get("error"):
            return self._error(request, "x_oauth_error", "X authorization returned an error.", 400)

        code = request.query_params.get("code")
        state = request.query_params.get("state")
        if not code or not state:
            return self._error(request, "invalid_request", "Missing code or state.", 400)

        pending = self.pending_auth.pop(state, None)
        if pending is None:
            return self._error(request, "invalid_state", "Unknown or expired state.", 400)

        try:
            exchanged = await self._exchange_code_fn(
                client_id=self.x_client_id,
                client_secret=self.x_client_secret,
                code=code,
                redirect_uri=f"{self.public_url}/x/callback",
                code_verifier=pending.x_code_verifier,
            )
        except Exception as error:
            return self._error(
                request,
                "x_token_exchange_failed",
                f"Failed to exchange X authorization code: {error}",
                502,
            )

        if self.allowed_user_id:
            try:
                user_id = await self._fetch_user_id_fn(exchanged.access_token)
            except Exception:
                return self._error(request, "user_check_failed", "Could not verify X user identity.", 502)
            if user_id != self.allowed_user_id:
                return self._error(request, "access_denied", "This X account is not allowed.", 403)

        issued_code = secrets.token_urlsafe(32)
        self.pending_codes[issued_code] = PendingCode(
            client_id=pending.client_id,
            code_challenge=pending.code_challenge,
            redirect_uri=pending.redirect_uri,
            x_access_token=exchanged.access_token,
            x_refresh_token=exchanged.refresh_token,
            x_expires_at=exchanged.expires_at,
            created_at=time.time(),
        )

        redirect_url = append_query_params(
            pending.redirect_uri,
            {
                "code": issued_code,
                "state": pending.original_state,
            },
        )
        return apply_cors_response(
            request,
            RedirectResponse(url=redirect_url, status_code=302),
            self.cors_origins,
        )

    async def _handle_token(self, request: Request) -> Response:
        self._cleanup_pending_codes()

        form = await request.form()
        form_data = {key: str(value) for key, value in form.multi_items()}
        client_id, client_secret = self._extract_client_auth(request, form_data)

        if not client_id or not client_secret:
            return self._error(request, "invalid_client", "Missing client credentials.", 401)

        client = self.client_registry.get(client_id)
        if client is None or client.client_secret != client_secret:
            return self._error(request, "invalid_client", "Invalid client credentials.", 401)

        grant_type = form_data.get("grant_type")
        if grant_type == "authorization_code":
            return await self._exchange_authorization_code(request, form_data, client_id)
        if grant_type == "refresh_token":
            return await self._exchange_refresh_token(request, form_data, client_id)

        return self._error(request, "unsupported_grant_type", "Unsupported grant_type.", 400)

    async def _exchange_authorization_code(
        self,
        request: Request,
        form_data: dict[str, str],
        client_id: str,
    ) -> Response:
        code = form_data.get("code")
        code_verifier = form_data.get("code_verifier")
        if not code or not code_verifier:
            return self._error(request, "invalid_request", "Missing code or code_verifier.", 400)

        pending_code = self.pending_codes.pop(code, None)
        if pending_code is None:
            return self._error(request, "invalid_grant", "Invalid authorization code.", 400)

        if time.time() - pending_code.created_at > self.pending_code_ttl_seconds:
            return self._error(request, "invalid_grant", "Authorization code expired.", 400)

        if pending_code.client_id != client_id:
            return self._error(
                request, "invalid_grant", "Authorization code does not match client.", 400
            )

        expected_code_challenge = x_oauth2.generate_code_challenge(code_verifier)
        if expected_code_challenge != pending_code.code_challenge:
            return self._error(request, "invalid_grant", "PKCE verification failed.", 400)

        access_token, refresh_token = self._mint_session_tokens(
            x_access_token=pending_code.x_access_token,
            x_refresh_token=pending_code.x_refresh_token,
            x_expires_at=pending_code.x_expires_at,
            client_id=client_id,
        )

        return apply_cors_response(
            request,
            JSONResponse(
                {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": 7200,
                    "refresh_token": refresh_token,
                }
            ),
            self.cors_origins,
        )

    async def _exchange_refresh_token(
        self,
        request: Request,
        form_data: dict[str, str],
        client_id: str,
    ) -> Response:
        session_refresh_token = form_data.get("refresh_token")
        if not session_refresh_token:
            return self._error(request, "invalid_request", "Missing refresh_token.", 400)

        try:
            payload = self.decode_session_token(session_refresh_token)
        except Exception:
            return self._error(request, "invalid_grant", "Invalid refresh_token.", 400)

        if payload.get("typ") != "r":
            return self._error(request, "invalid_grant", "Invalid refresh_token.", 400)
        if payload.get("cid") != client_id:
            return self._error(
                request, "invalid_grant", "Refresh token does not match client.", 400
            )

        x_access_token = payload["xat"]
        x_refresh_token = payload["xrt"]
        x_expires_at = payload["xexp"]

        if x_expires_at <= time.time():
            try:
                refreshed = await self._refresh_token_fn(
                    client_id=self.x_client_id,
                    client_secret=self.x_client_secret,
                    refresh_token=x_refresh_token,
                )
            except Exception as error:
                return self._error(
                    request,
                    "invalid_grant",
                    f"X refresh token expired or revoked; re-auth required: {error}",
                    401,
                )
            x_access_token = refreshed.access_token
            x_refresh_token = refreshed.refresh_token
            x_expires_at = refreshed.expires_at

        access_token, refresh_token = self._mint_session_tokens(
            x_access_token=x_access_token,
            x_refresh_token=x_refresh_token,
            x_expires_at=x_expires_at,
            client_id=client_id,
        )

        return apply_cors_response(
            request,
            JSONResponse(
                {
                    "access_token": access_token,
                    "token_type": "bearer",
                    "expires_in": 7200,
                    "refresh_token": refresh_token,
                }
            ),
            self.cors_origins,
        )

    # -- helpers ---------------------------------------------------------------

    def _cleanup_pending_auth(self) -> None:
        cutoff = time.time() - self.pending_auth_ttl_seconds
        expired_states = [
            state for state, pending in self.pending_auth.items() if pending.created_at < cutoff
        ]
        for state in expired_states:
            del self.pending_auth[state]

    def _cleanup_pending_codes(self) -> None:
        cutoff = time.time() - self.pending_code_ttl_seconds
        expired_codes = [
            code for code, pending in self.pending_codes.items() if pending.created_at < cutoff
        ]
        for code in expired_codes:
            del self.pending_codes[code]

    def _extract_client_auth(
        self,
        request: Request,
        form_data: dict[str, str],
    ) -> tuple[str | None, str | None]:
        header = request.headers.get("authorization")
        if header and header.lower().startswith("basic "):
            raw = header.split(" ", 1)[1].strip()
            try:
                decoded = base64.b64decode(raw).decode("utf-8")
            except (binascii.Error, UnicodeDecodeError):
                return None, None

            if ":" not in decoded:
                return None, None
            client_id, client_secret = decoded.split(":", 1)
            return client_id, client_secret

        return form_data.get("client_id"), form_data.get("client_secret")

    def _error(self, request: Request, code: str, description: str, status_code: int) -> Response:
        return cors_error_response(
            request=request,
            allowed_origins=self.cors_origins,
            code=code,
            description=description,
            status_code=status_code,
        )
