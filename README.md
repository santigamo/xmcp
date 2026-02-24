# X API FastMCP Server

Run a local MCP server that exposes the X API OpenAPI spec as tools using
FastMCP. Streaming and webhook endpoints are excluded.

## Prerequisites

- Python 3.12+
- An X Developer Platform app (to get tokens)
- Optional: an xAI API key if you want to run the Grok test client

## Setup (local)

1. Create a virtual environment and install dependencies:
   - `python -m venv .venv`
   - `source .venv/bin/activate`
   - `pip install -e ".[dev]"`
2. Create your local `.env`:
   - `cp env.example .env`
   - Required values (do not skip):
     - `X_OAUTH_CONSUMER_KEY`
     - `X_OAUTH_CONSUMER_SECRET`
     - `X_BEARER_TOKEN` (required for this setup; keep it set even if using OAuth1)
   - OAuth1 callback (defaults are fine):
     - `X_OAUTH_CALLBACK_HOST` (default `127.0.0.1`)
     - `X_OAUTH_CALLBACK_PORT` (default `8976`)
     - `X_OAUTH_CALLBACK_PATH` (default `/oauth/callback`)
     - `X_OAUTH_CALLBACK_TIMEOUT` (default `300`)
   - Server settings (optional):
     - `X_API_BASE_URL` (default `https://api.x.com`)
     - `X_API_TIMEOUT` (default `30`)
     - `MCP_HOST` (default `127.0.0.1`)
     - `MCP_PORT` (default `8000`)
     - `X_API_DEBUG` (default `1`)
     - `X_AUTH_MODE` (`oauth1` by default; use `oauth2-remote` for Claude connector flow)
  - Tool filtering (optional, comma-separated):
    - `X_API_TOOL_ALLOWLIST`
   - Optional Grok test client:
     - `XAI_API_KEY`
     - `XAI_MODEL` (default `grok-4-1-fast`)
     - `MCP_SERVER_URL` (default `http://127.0.0.1:8000/mcp`)
   - Optional OAuth2 token generation:
     - `CLIENT_ID`
     - `CLIENT_SECRET`
     - `X_OAUTH_ACCESS_TOKEN`
    - `X_OAUTH_ACCESS_TOKEN_SECRET` (optional)
   - OAuth2 remote mode (required when `X_AUTH_MODE=oauth2-remote`):
     - `X_OAUTH2_CLIENT_ID`
     - `X_OAUTH2_CLIENT_SECRET`
     - `X_MCP_PUBLIC_URL` (public HTTPS URL of this server)
     - `X_OAUTH2_SCOPES` (default `tweet.read tweet.write users.read offline.access`)
     - `X_TOKEN_STORE_PATH` (default `.tokens.json`)
     - `X_CORS_ORIGINS` (optional extra allowed origins, comma-separated)
   - Optional OAuth1 debug output:
     - `X_OAUTH_PRINT_TOKENS`
     - `X_OAUTH_PRINT_AUTH_HEADER`
3. Register the callback URL in your X Developer App:

```
http://<X_OAUTH_CALLBACK_HOST>:<X_OAUTH_CALLBACK_PORT><X_OAUTH_CALLBACK_PATH>
```

Example (defaults):

```
http://127.0.0.1:8976/oauth/callback
```

4. Start the server:

```bash
python server.py
```

The MCP endpoint is `http://127.0.0.1:8000/mcp` by default.

5. Connect an MCP client:
- Local client: point it to `http://127.0.0.1:8000/mcp`.
- Remote client: tunnel your local server (e.g., ngrok) and use the public URL.

## Docker deployment

1. Create a runtime `.env` file:
   - `cp env.example .env`
   - Fill the required auth values (`X_OAUTH_CONSUMER_KEY`, `X_OAUTH_CONSUMER_SECRET`, `X_BEARER_TOKEN`)
2. Start the server with Docker Compose:

```bash
docker compose up --build
```

3. MCP endpoint:
   - `http://127.0.0.1:8000/mcp`

`docker-compose.yml` sets `MCP_HOST=0.0.0.0` for container networking, while local
non-Docker runs keep `MCP_HOST=127.0.0.1` by default.

## Quality checks

Run the baseline Sprint 0 checks locally:

```bash
ruff check .
pytest
```

## Whitelisting tools

Use `X_API_TOOL_ALLOWLIST` to load a small, explicit set of tools:

```
X_API_TOOL_ALLOWLIST=getUsersByUsername,createPosts,searchPostsRecent
```

Whitelisting is applied at startup when the OpenAPI spec is loaded, so restart
the server after changes. See the full tool list below before building your
allowlist.

## Safety annotations

OpenAPI-generated tools are annotated automatically for MCP clients:

- `GET`/`HEAD`/`OPTIONS` -> `readOnlyHint=true`, `destructiveHint=false`, `openWorldHint=true`
- `DELETE` -> `readOnlyHint=false`, `destructiveHint=true`, `openWorldHint=true`
- `POST`/`PUT`/`PATCH` (and unknown methods) -> `readOnlyHint=false`, `destructiveHint=false`, `openWorldHint=true`

Optional per-operation overrides are loaded from `annotation_overrides.json` at
startup. Keys are OpenAPI `operationId` values, for example:

```json
{
  "hideReply": {"destructiveHint": true}
}
```

## OAuth1 flow (startup behavior)

On startup, the server opens a browser for OAuth1 consent and waits for the
callback. Tokens are kept in memory only for the lifetime of the server
process. Set `X_OAUTH_PRINT_TOKENS=1` to print tokens, or
`X_OAUTH_PRINT_AUTH_HEADER=1` to print request headers.

## Available tool calls (allowlist-ready)

Below is the full list of tool calls you can whitelist via
`X_API_TOOL_ALLOWLIST`. Copy any of these into your `.env` allowlist.

- `addListsMember`
- `addUserPublicKey`
- `appendMediaUpload`
- `blockUsersDms`
- `createCommunityNotes`
- `createComplianceJobs`
- `createDirectMessagesByConversationId`
- `createDirectMessagesByParticipantId`
- `createDirectMessagesConversation`
- `createLists`
- `createMediaMetadata`
- `createMediaSubtitles`
- `createPosts`
- `createUsersBookmark`
- `deleteActivitySubscription`
- `deleteAllConnections`
- `deleteCommunityNotes`
- `deleteConnectionsByEndpoint`
- `deleteConnectionsByUuids`
- `deleteDirectMessagesEvents`
- `deleteLists`
- `deleteMediaSubtitles`
- `deletePosts`
- `deleteUsersBookmark`
- `evaluateCommunityNotes`
- `finalizeMediaUpload`
- `followList`
- `followUser`
- `getAccountActivitySubscriptionCount`
- `getActivitySubscriptions`
- `getChatConversation`
- `getChatConversations`
- `getCommunitiesById`
- `getComplianceJobs`
- `getComplianceJobsById`
- `getConnectionHistory`
- `getDirectMessagesEvents`
- `getDirectMessagesEventsByConversationId`
- `getDirectMessagesEventsById`
- `getDirectMessagesEventsByParticipantId`
- `getInsights28Hr`
- `getInsightsHistorical`
- `getListsById`
- `getListsFollowers`
- `getListsMembers`
- `getListsPosts`
- `getMarketplaceHandleAvailability`
- `getMediaAnalytics`
- `getMediaByMediaKey`
- `getMediaByMediaKeys`
- `getMediaUploadStatus`
- `getNews`
- `getOpenApiSpec`
- `getPostsAnalytics`
- `getPostsById`
- `getPostsByIds`
- `getPostsCountsAll`
- `getPostsCountsRecent`
- `getPostsLikingUsers`
- `getPostsQuotedPosts`
- `getPostsRepostedBy`
- `getPostsReposts`
- `getSpacesBuyers`
- `getSpacesByCreatorIds`
- `getSpacesById`
- `getSpacesByIds`
- `getSpacesPosts`
- `getTrendsByWoeid`
- `getTrendsPersonalizedTrends`
- `getUsage`
- `getUserPublicKeys`
- `getUsersAffiliates`
- `getUsersBlocking`
- `getUsersBookmarkFolders`
- `getUsersBookmarks`
- `getUsersBookmarksByFolderId`
- `getUsersById`
- `getUsersByIds`
- `getUsersByUsername`
- `getUsersByUsernames`
- `getUsersFollowedLists`
- `getUsersFollowers`
- `getUsersFollowing`
- `getUsersLikedPosts`
- `getUsersListMemberships`
- `getUsersMe`
- `getUsersMentions`
- `getUsersMuting`
- `getUsersOwnedLists`
- `getUsersPinnedLists`
- `getUsersPosts`
- `getUsersRepostsOfMe`
- `getUsersTimeline`
- `hidePostsReply`
- `initializeMediaUpload`
- `likePost`
- `mediaUpload`
- `muteUser`
- `pinList`
- `removeListsMemberByUserId`
- `repostPost`
- `searchCommunities`
- `searchCommunityNotesWritten`
- `searchEligiblePosts`
- `searchNews`
- `searchPostsAll`
- `searchPostsRecent`
- `searchSpaces`
- `searchUsers`
- `sendChatMessage`
- `unblockUsersDms`
- `unfollowList`
- `unfollowUser`
- `unlikePost`
- `unmuteUser`
- `unpinList`
- `unrepostPost`
- `updateActivitySubscription`
- `updateLists`

## Generate an OAuth2 user token (optional)

1. Add `CLIENT_ID` and `CLIENT_SECRET` to your `.env`.
2. Update `redirect_uri` in `generate_authtoken.py` to match your app settings.
3. Run `python generate_authtoken.py` and follow the prompts.
4. Copy the printed access token into `.env` as `X_OAUTH_ACCESS_TOKEN`.
   If your flow returns a secret, store it as `X_OAUTH_ACCESS_TOKEN_SECRET`.

## OAuth2 client modules (Sprint 3)

The OAuth2 integration layer is split into standalone modules under `auth/`:

- `auth/x_oauth2.py`: PKCE helpers, authorization URL builder, token exchange and refresh
- `auth/token_store.py`: async token store abstraction with in-memory and file-backed adapters
- `auth/client_registry.py`: in-memory dynamic client registry for OAuth clients

Run Sprint 3 verification directly:

```bash
pytest tests/test_x_oauth2.py tests/test_token_store.py tests/test_client_registry.py -v
```

## OAuth2 remote auth server (Sprint 4)

When `X_AUTH_MODE=oauth2-remote`, xmcp mounts OAuth endpoints and uses MCP
Bearer tokens to resolve per-user X access tokens at request time.

Mounted endpoints:

- `GET /.well-known/oauth-authorization-server`
- `POST /register`
- `GET /authorize`
- `GET /x/callback`
- `POST /token`

Run Sprint 4 verification:

```bash
pytest tests/test_oauth_server.py tests/test_auth_mode.py tests/test_auth_middleware.py tests/test_cors.py -v
```

## Run the Grok MCP test client (optional)

1. Set `XAI_API_KEY` in `.env`.
2. Make sure your MCP server is running locally (or set `MCP_SERVER_URL`).
3. If Grok is not running on your machine, use ngrok to expose your local MCP
   server and set `MCP_SERVER_URL` to the public HTTPS URL that ends with `/mcp`.
   Example flow: `ngrok http 8000` then `MCP_SERVER_URL=https://<id>.ngrok-free.dev/mcp`.
4. Run `python examples/test_grok_mcp.py`.

## Notes

- Endpoints with `/stream` or `/webhooks` in the path are excluded.
- Operations tagged `Stream` or `Webhooks`, or marked with
  `x-twitter-streaming: true`, are excluded.
- The OpenAPI spec is fetched from `https://api.twitter.com/2/openapi.json` at
  startup.
