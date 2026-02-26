import { Container } from "@cloudflare/containers";
import { env } from "cloudflare:workers";

interface Env {
  XMCP: DurableObjectNamespace<XmcpContainer>;
}

export class XmcpContainer extends Container {
  defaultPort = 8000;
  sleepAfter = "30m";

  override get envVars(): Record<string, string> {
    return {
      MCP_HOST: "0.0.0.0",
      MCP_PORT: "8000",
      X_OAUTH2_CLIENT_ID: env.X_OAUTH2_CLIENT_ID ?? "",
      X_OAUTH2_CLIENT_SECRET: env.X_OAUTH2_CLIENT_SECRET ?? "",
      X_MCP_PUBLIC_URL: env.X_MCP_PUBLIC_URL ?? "",
      X_ALLOWED_USER_ID: env.X_ALLOWED_USER_ID ?? "",
      X_BEARER_TOKEN: env.X_BEARER_TOKEN ?? "",
      X_OAUTH2_SCOPES:
        env.X_OAUTH2_SCOPES ??
        "tweet.read tweet.write users.read offline.access",
    };
  }
}

export default {
  async fetch(request: Request, env: Env): Promise<Response> {
    const container = env.XMCP.getByName("xmcp");
    return container.fetch(request);
  },
};
