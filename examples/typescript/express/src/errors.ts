// Every error this application returns has the same body:
// {"error": {"code": "...", "message": "..."}}

export class HttpError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "HttpError";
  }
}

export const missingToken = () => new HttpError(401, "missing_token", "a bearer access token is required");
export const invalidToken = (message = "the access token is invalid") => new HttpError(401, "invalid_token", message);
export const tokenExpired = () => new HttpError(401, "token_expired", "the access token has expired");
export const forbidden = () => new HttpError(403, "forbidden", "you do not have permission to perform this action");
export const identityUnavailable = () => new HttpError(502, "identity_unavailable", "the identity service is unavailable");
