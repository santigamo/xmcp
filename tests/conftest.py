import pytest


@pytest.fixture
def mock_openapi_spec() -> dict:
    return {
        "openapi": "3.0.0",
        "info": {"title": "X API", "version": "1.0.0"},
        "components": {
            "parameters": {
                "CommaSeparatedComponentParam": {
                    "name": "component_ids",
                    "in": "query",
                    "schema": {"type": "array", "items": {"type": "string"}},
                    "explode": False,
                },
                "PlainComponentParam": {
                    "name": "cursor",
                    "in": "query",
                    "schema": {"type": "string"},
                },
            }
        },
        "paths": {
            "/2/users/by/username/{username}": {
                "get": {
                    "operationId": "getUsersByUsername",
                    "tags": ["users"],
                    "parameters": [
                        {
                            "name": "username",
                            "in": "path",
                            "required": True,
                            "schema": {"type": "string"},
                        }
                    ],
                }
            },
            "/2/posts": {
                "post": {
                    "operationId": "createPosts",
                    "tags": ["posts"],
                    "parameters": [
                        {
                            "name": "inline_ids",
                            "in": "query",
                            "schema": {"type": "array", "items": {"type": "string"}},
                            "explode": False,
                        },
                        {
                            "name": "tweet.fields",
                            "in": "query",
                            "schema": {"type": "string"},
                        },
                    ],
                }
            },
            "/2/posts/{id}": {
                "delete": {
                    "operationId": "deletePosts",
                    "tags": ["posts"],
                }
            },
            "/2/posts/stream/sample": {
                "get": {
                    "operationId": "getPostsSampleStream",
                    "tags": ["posts"],
                }
            },
            "/2/webhooks/events": {
                "post": {
                    "operationId": "createWebhooksEvent",
                    "tags": ["events"],
                }
            },
            "/2/tweets/live": {
                "get": {
                    "operationId": "getTweetsLive",
                    "tags": ["stream"],
                }
            },
            "/2/tweets/sampled": {
                "get": {
                    "operationId": "getTweetsSampled",
                    "tags": ["tweets"],
                    "x-twitter-streaming": True,
                }
            },
        },
    }
