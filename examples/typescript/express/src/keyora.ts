// Calls Keyora's REST API on behalf of this application. The client holds the
// client secret, which is why it lives on the server and never in a browser.

import type { Config } from "./config.js";

/** Keyora's response shape: `data` on success, `error` on failure. */
export interface Envelope {
  data?: unknown;
  error?: unknown;
}

export interface KeyoraResponse {
  status: number;
  body: Envelope;
}

/** The live state of a token as reported by Keyora. */
export interface Introspection {
  active: boolean;
  sub?: string;
  email?: string;
  roles?: string[];
  permissions?: string[];
}

/** Keyora could not be reached or answered with something that is not its API. */
export class KeyoraUnavailableError extends Error {
  constructor(message: string, options?: ErrorOptions) {
    super(message, options);
    this.name = "KeyoraUnavailableError";
  }
}

export class KeyoraClient {
  readonly #baseUrl: string;
  readonly #authorization: string;

  constructor(config: Pick<Config, "keyoraUrl" | "clientId" | "clientSecret">) {
    this.#baseUrl = config.keyoraUrl;
    // HTTP Basic: client_id as the username, client_secret as the password.
    this.#authorization = "Basic " + Buffer.from(`${config.clientId}:${config.clientSecret}`).toString("base64");
  }

  /** Sends a JSON body with the application's credentials and returns Keyora's status and envelope. */
  async post(path: string, body: unknown): Promise<KeyoraResponse> {
    let res: Response;
    try {
      res = await fetch(this.#baseUrl + path, {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          Accept: "application/json",
          Authorization: this.#authorization,
        },
        body: JSON.stringify(body),
        signal: AbortSignal.timeout(10_000),
      });
    } catch (cause) {
      throw new KeyoraUnavailableError(`keyora unreachable: POST ${path}`, { cause });
    }

    const text = await res.text();
    if (text === "") {
      return { status: res.status, body: {} }; // 204 and 202 have no body
    }
    try {
      const parsed: unknown = JSON.parse(text);
      if (typeof parsed === "object" && parsed !== null) {
        return { status: res.status, body: parsed as Envelope };
      }
    } catch {
      // fall through
    }
    throw new KeyoraUnavailableError(`unexpected response from keyora: POST ${path} -> ${res.status}`);
  }

  /** Asks Keyora whether a token is valid right now (session not revoked, user active). */
  async introspect(token: string): Promise<Introspection> {
    const { status, body } = await this.post("/api/v1/auth/introspect", { token });
    const data = body.data;
    if (status !== 200 || typeof data !== "object" || data === null || typeof (data as Introspection).active !== "boolean") {
      throw new KeyoraUnavailableError(`introspection failed with status ${status}`);
    }
    return data as Introspection;
  }
}
