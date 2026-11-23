// Settings come from the environment (see examples/.env, written by examples/setup.sh).

export interface Config {
  keyoraUrl: string;
  issuer: string;
  clientId: string;
  clientSecret: string;
  port: number;
}

export function loadConfig(env: NodeJS.ProcessEnv = process.env): Config {
  const keyoraUrl = (env.KEYORA_URL || "http://localhost:8080").replace(/\/+$/, "");
  const clientId = env.KEYORA_CLIENT_ID ?? "";
  const clientSecret = env.KEYORA_CLIENT_SECRET ?? "";
  if (!clientId || !clientSecret) {
    throw new Error("KEYORA_CLIENT_ID and KEYORA_CLIENT_SECRET are required (run examples/setup.sh and load examples/.env)");
  }
  const port = Number(env.PORT || 9003);
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    throw new Error(`PORT must be a port number, got "${env.PORT}"`);
  }
  return {
    keyoraUrl,
    // The issuer differs from the URL only when Keyora is reached on an
    // internal address, for example from inside a container.
    issuer: env.KEYORA_ISSUER || keyoraUrl,
    clientId,
    clientSecret,
    port,
  };
}
