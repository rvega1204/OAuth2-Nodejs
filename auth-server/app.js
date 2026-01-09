/**
 * @fileoverview OAuth 2.0 Authorization Server (demo) with PKCE and JWT access tokens.
 *
 * Endpoints:
 * - GET /authorize: Issues authorization codes (PKCE required).
 * - POST /token: Exchanges codes for tokens and supports refresh tokens.
 * - GET /.well-known/jwks.json: Publishes the public key for JWT verification.
 */

import express from "express";
import bodyParser from "body-parser";
import cookieParser from "cookie-parser";
import { randomBytes, createHash, generateKeyPairSync } from "crypto";
import { SignJWT, exportJWK, importPKCS8, importSPKI } from "jose";

/**
 * Encodes a Buffer into base64url (RFC 4648 URL-safe base64 without padding).
 * @param {!Buffer} input
 * @return {string}
 */
export function base64Url(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

/**
 * Computes SHA-256 and returns base64url-encoded output (used for PKCE S256).
 * @param {string} str
 * @return {string}
 */
export function sha256Base64Url(str) {
  const hash = createHash("sha256").update(str).digest();
  return base64Url(hash);
}

/**
 * Generates a cryptographically-random, URL-safe code/token value.
 * @return {string}
 */
export function generateCode() {
  return base64Url(randomBytes(32));
}

/**
 * Returns the demo user identity (no real authentication in this tutorial server).
 * @return {{sub: string, name: string, email: string}}
 */
export function getDemoUser() {
  return { sub: "alice", name: "Alice Example", email: "alice@example.com" };
}

/**
 * Generates an RSA key pair for signing JWTs (RS256).
 *
 * Notes:
 * - modulusLength=2048 is a common baseline for RSA security/performance tradeoffs.
 * - Private key is exported as PKCS#8 PEM; public key as SPKI PEM (JWKS-compatible).
 *
 * @return {{privateKey: string, publicKey: string}}
 */
export function generateKeyPair() {
  return generateKeyPairSync("rsa", {
    modulusLength: 2048,
    privateKeyEncoding: { type: "pkcs8", format: "pem" },
    publicKeyEncoding: { type: "spki", format: "pem" },
  });
}

/**
 * Creates and configures the Express application for the authorization server.
 * 
 * @param {Object} options - Configuration options
 * @param {string} options.issuer - Issuer URL (default: http://localhost:3000)
 * @param {string} options.keyId - Key ID for JWKS (default: demo-key-1)
 * @param {Object} options.keyPair - Pre-generated key pair (optional, will generate if not provided)
 * @returns {Object} Object containing the app and key pair
 */
export function createApp(options = {}) {
  const ISSUER = options.issuer || "http://localhost:3000";
  const KEY_ID = options.keyId || "demo-key-1";
  
  // Generate or use provided key pair
  const keyPair = options.keyPair || generateKeyPair();
  const PRIVATE_KEY_PEM = keyPair.privateKey;
  const PUBLIC_KEY_PEM = keyPair.publicKey;

  const app = express();
  app.use(bodyParser.urlencoded({ extended: false }));
  app.use(bodyParser.json());
  app.use(cookieParser());

  /** @const {!Map<string, {client_id: string, redirectUris: !Array<string>}>} */
  const clients = new Map();

  /**
   * Authorization code store (in-memory demo).
   * @const {!Map<string, {
   *   clientId: string,
   *   redirectUri: string,
   *   codeChallenge: string,
   *   scope: string,
   *   user: {sub: string, name: string, email: string},
   *   expiresAt: number
   * }>}
   */
  const authorizationCodes = new Map();

  /**
   * Refresh token store (in-memory demo).
   * @const {!Map<string, {sub: string, scope: string, clientId: string}>}
   */
  const refreshTokens = new Map();

  clients.set("demo-client", {
    client_id: "demo-client",
    redirectUris: ["http://localhost:4000/callback"],
  });

  /**
   * Authorization endpoint (demo).
   *
   * Validates client_id, redirect_uri, response_type=code, and PKCE S256 parameters.
   * Creates a short-lived authorization code bound to (client_id, redirect_uri, code_challenge).
   *
   * @param {!express.Request} req
   * @param {!express.Response} res
   * @return {void}
   */
  app.get("/authorize", (req, res) => {
    const {
      response_type,
      client_id,
      redirect_uri,
      scope = "",
      state,
      code_challenge,
      code_challenge_method,
    } = req.query;

    const client = clients.get(client_id);
    if (!client) return res.status(400).send("Unknown client_id");
    if (!client.redirectUris.includes(redirect_uri)) {
      return res.status(400).send("Invalid redirect_uri");
    }
    if (response_type !== "code") {
      return res.status(400).send("Only response_type=code supported");
    }
    if (!code_challenge || code_challenge_method !== "S256") {
      return res.status(400).send(
        "PKCE required: provide code_challenge and code_challenge_method=S256"
      );
    }

    // Demo behavior: auto-login and auto-consent.
    const user = getDemoUser();

    const code = generateCode();
    authorizationCodes.set(code, {
      clientId: client_id,
      redirectUri: redirect_uri,
      codeChallenge: code_challenge,
      scope,
      user,
      expiresAt: Date.now() + 5 * 60 * 1000,
    });

    const redirect = new URL(redirect_uri);
    redirect.searchParams.set("code", code);
    if (state) redirect.searchParams.set("state", state);

    res.redirect(redirect.toString());
  });

  /**
   * Token endpoint.
   *
   * Supported grants:
   * - authorization_code (PKCE required)
   * - refresh_token
   *
   * @param {!express.Request} req
   * @param {!express.Response} res
   * @return {Promise<void>}
   */
  app.post("/token", async (req, res) => {
    try {
      const { grant_type } = req.body;

      if (grant_type === "authorization_code") {
        const { code, redirect_uri, client_id, code_verifier } = req.body;

        const record = authorizationCodes.get(code);
        if (!record) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Unknown code",
          });
        }

        if (record.expiresAt < Date.now()) {
          authorizationCodes.delete(code);
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Code expired",
          });
        }

        if (record.clientId !== client_id || record.redirectUri !== redirect_uri) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "Client mismatch",
          });
        }

        // PKCE S256 verification: base64url(sha256(code_verifier)) must match code_challenge.
        const computedChallenge = sha256Base64Url(code_verifier);
        if (computedChallenge !== record.codeChallenge) {
          return res.status(400).json({
            error: "invalid_grant",
            error_description: "PKCE validation failed",
          });
        }

        // Enforce one-time use for authorization codes.
        authorizationCodes.delete(code);

        const privateKeyObj = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

        const accessToken = await new SignJWT({
          scope: record.scope,
          name: record.user.name,
          email: record.user.email,
        })
          .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
          .setIssuer(ISSUER)
          .setAudience(client_id)
          .setSubject(record.user.sub)
          .setIssuedAt()
          .setExpirationTime("15m")
          .sign(privateKeyObj);

        const refresh_token = generateCode();
        refreshTokens.set(refresh_token, {
          sub: record.user.sub,
          scope: record.scope,
          clientId: client_id,
        });

        return res.json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 900,
          refresh_token,
          scope: record.scope,
        });
      }

      if (grant_type === "refresh_token") {
        const { refresh_token, client_id } = req.body;

        const record = refreshTokens.get(refresh_token);
        if (!record) return res.status(400).json({ error: "invalid_grant" });
        if (record.clientId !== client_id) {
          return res.status(400).json({ error: "invalid_grant" });
        }

        const privateKeyObj = await importPKCS8(PRIVATE_KEY_PEM, "RS256");

        const accessToken = await new SignJWT({ scope: record.scope })
          .setProtectedHeader({ alg: "RS256", kid: KEY_ID })
          .setIssuer(ISSUER)
          .setAudience(client_id)
          .setSubject(record.sub)
          .setIssuedAt()
          .setExpirationTime("15m")
          .sign(privateKeyObj);

        return res.json({
          access_token: accessToken,
          token_type: "Bearer",
          expires_in: 900,
        });
      }

      res.status(400).json({ error: "unsupported_grant_type" });
    } catch (err) {
      console.error("Token endpoint error:", err);
      res.status(500).json({ error: "server_error", error_description: err.message });
    }
  });

  /**
   * JWKS endpoint for resource servers to retrieve public keys used for JWT verification.
   * @param {!express.Request} req
   * @param {!express.Response} res
   * @return {Promise<void>}
   */
  app.get("/.well-known/jwks.json", async (req, res) => {
    try {
      const publicKeyObj = await importSPKI(PUBLIC_KEY_PEM, "RS256");
      const jwk = await exportJWK(publicKeyObj);

      jwk.use = "sig";
      jwk.alg = "RS256";
      jwk.kid = KEY_ID;

      res.status(200).json({ keys: [jwk] });
    } catch (err) {
      console.error("JWKS endpoint error:", err);
      res.status(500).json({ error: "server_error" });
    }
  });

  // Expose stores for testing purposes
  app._stores = {
    clients,
    authorizationCodes,
    refreshTokens
  };

  return { app, keyPair: { privateKey: PRIVATE_KEY_PEM, publicKey: PUBLIC_KEY_PEM } };
}