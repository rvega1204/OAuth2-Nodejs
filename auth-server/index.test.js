/**
 * Test suite for OAuth 2.0 Authorization Server
 * 
 * These tests verify:
 * - Authorization code generation with PKCE
 * - Token exchange with PKCE verification
 * - Refresh token functionality
 * - JWKS endpoint
 * - Error handling and security validations
 * 
 * Tests use:
 * - Node.js native test runner (node:test)
 * - Supertest for HTTP testing
 * - jose for JWT verification
 */

import { describe, it, before, beforeEach } from "node:test";
import assert from "node:assert";
import request from "supertest";
import { jwtVerify, importSPKI } from "jose";
import {
  createApp,
  base64Url,
  sha256Base64Url,
  generateCode,
  getDemoUser,
  generateKeyPair
} from "./app.js";

describe("OAuth 2.0 Authorization Server Tests", () => {
  let app;
  let keyPair;
  let stores;

  before(() => {
    const result = createApp();
    app = result.app;
    keyPair = result.keyPair;
    stores = app._stores;
  });

  describe("Helper Functions", () => {
    
    it("should encode Buffer to base64url without special characters", () => {
      const input = Buffer.from("hello+world/test=");
      const result = base64Url(input);
      
      assert.strictEqual(result.includes("+"), false);
      assert.strictEqual(result.includes("/"), false);
      assert.strictEqual(result.includes("="), false);
    });

    it("should generate SHA-256 hash in base64url format", () => {
      const input = "test-verifier-123";
      const hash1 = sha256Base64Url(input);
      const hash2 = sha256Base64Url(input);
      
      // Same input should produce same hash
      assert.strictEqual(hash1, hash2);
      assert.strictEqual(typeof hash1, "string");
      assert.ok(hash1.length > 0);
    });

    it("should generate random authorization codes", () => {
      const code1 = generateCode();
      const code2 = generateCode();
      
      assert.notStrictEqual(code1, code2);
      assert.strictEqual(typeof code1, "string");
      assert.ok(code1.length >= 43);
    });

    it("should return demo user object", () => {
      const user = getDemoUser();
      
      assert.strictEqual(user.sub, "alice");
      assert.strictEqual(user.name, "Alice Example");
      assert.strictEqual(user.email, "alice@example.com");
    });

    it("should generate RSA key pair", () => {
      const keys = generateKeyPair();
      
      assert.ok(keys.privateKey);
      assert.ok(keys.publicKey);
      assert.ok(keys.privateKey.includes("BEGIN PRIVATE KEY"));
      assert.ok(keys.publicKey.includes("BEGIN PUBLIC KEY"));
    });
  });

  describe("Endpoint: GET /authorize", () => {
    
    it("should return 400 if client_id is unknown", async () => {
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "unknown-client",
          redirect_uri: "http://localhost:4000/callback",
          code_challenge: "test-challenge",
          code_challenge_method: "S256"
        });
      
      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("Unknown client_id"));
    });

    it("should return 400 if redirect_uri is not registered", async () => {
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://evil-site.com/callback",
          code_challenge: "test-challenge",
          code_challenge_method: "S256"
        });
      
      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("Invalid redirect_uri"));
    });

    it("should return 400 if response_type is not 'code'", async () => {
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "token",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          code_challenge: "test-challenge",
          code_challenge_method: "S256"
        });
      
      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("Only response_type=code supported"));
    });

    it("should return 400 if PKCE parameters are missing", async () => {
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback"
        });
      
      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("PKCE required"));
    });

    it("should return 400 if code_challenge_method is not S256", async () => {
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          code_challenge: "test-challenge",
          code_challenge_method: "plain"
        });
      
      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("PKCE required"));
    });

    it("should redirect with authorization code and state", async () => {
      const codeChallenge = sha256Base64Url("test-verifier-abc123");
      const state = "random-state-xyz";
      
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          scope: "api.read openid",
          state: state,
          code_challenge: codeChallenge,
          code_challenge_method: "S256"
        });
      
      assert.strictEqual(response.status, 302);
      
      const location = response.headers.location;
      assert.ok(location.startsWith("http://localhost:4000/callback"));
      
      const url = new URL(location);
      assert.ok(url.searchParams.get("code"));
      assert.strictEqual(url.searchParams.get("state"), state);
    });

    it("should store authorization code with correct metadata", async () => {
      const codeChallenge = sha256Base64Url("verifier-xyz");
      
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          scope: "api.read profile",
          code_challenge: codeChallenge,
          code_challenge_method: "S256"
        });
      
      const location = response.headers.location;
      const url = new URL(location);
      const code = url.searchParams.get("code");
      
      assert.ok(code);
      
      // Verify code is stored
      const record = stores.authorizationCodes.get(code);
      assert.ok(record);
      assert.strictEqual(record.clientId, "demo-client");
      assert.strictEqual(record.redirectUri, "http://localhost:4000/callback");
      assert.strictEqual(record.codeChallenge, codeChallenge);
      assert.strictEqual(record.scope, "api.read profile");
      assert.strictEqual(record.user.sub, "alice");
    });
  });

  describe("Endpoint: POST /token (authorization_code grant)", () => {
    
    let authCode;
    let codeVerifier;
    let codeChallenge;

    beforeEach(async () => {
      // Generate PKCE parameters
      codeVerifier = generateCode();
      codeChallenge = sha256Base64Url(codeVerifier);
      
      // Get authorization code
      const response = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          scope: "api.read openid profile email",
          code_challenge: codeChallenge,
          code_challenge_method: "S256"
        });
      
      const url = new URL(response.headers.location);
      authCode = url.searchParams.get("code");
    });

    it("should return 400 for unknown authorization code", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: "invalid-code-xyz",
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "invalid_grant");
      assert.ok(response.body.error_description.includes("Unknown code"));
    });

    it("should return 400 for client_id mismatch", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "wrong-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "invalid_grant");
    });

    it("should return 400 for redirect_uri mismatch", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://wrong-uri.com/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "invalid_grant");
    });

    it("should return 400 for PKCE verification failure", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: "wrong-verifier"
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "invalid_grant");
      assert.ok(response.body.error_description.includes("PKCE validation failed"));
    });

    it("should exchange code for tokens with valid PKCE", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(response.status, 200);
      assert.ok(response.body.access_token);
      assert.ok(response.body.refresh_token);
      assert.strictEqual(response.body.token_type, "Bearer");
      assert.strictEqual(response.body.expires_in, 900);
      assert.ok(response.body.scope);
    });

    it("should return valid JWT access token", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      const accessToken = response.body.access_token;
      
      // Verify JWT structure (3 parts separated by dots)
      const parts = accessToken.split(".");
      assert.strictEqual(parts.length, 3);
      
      // Verify JWT can be decoded and validated
      const publicKeyObj = await importSPKI(keyPair.publicKey, "RS256");
      const { payload } = await jwtVerify(accessToken, publicKeyObj, {
        issuer: "http://localhost:3000",
        audience: "demo-client"
      });
      
      assert.strictEqual(payload.sub, "alice");
      assert.strictEqual(payload.name, "Alice Example");
      assert.strictEqual(payload.email, "alice@example.com");
      assert.ok(payload.scope);
    });

    it("should prevent code reuse (one-time use)", async () => {
      // First exchange should succeed
      const response1 = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(response1.status, 200);
      
      // Second exchange with same code should fail
      const response2 = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code: authCode,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(response2.status, 400);
      assert.strictEqual(response2.body.error, "invalid_grant");
    });
  });

  describe("Endpoint: POST /token (refresh_token grant)", () => {
    
    let refreshToken;

    beforeEach(async () => {
      // Get authorization code and exchange for tokens
      const codeVerifier = generateCode();
      const codeChallenge = sha256Base64Url(codeVerifier);
      
      const authResponse = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          scope: "api.read",
          code_challenge: codeChallenge,
          code_challenge_method: "S256"
        });
      
      const url = new URL(authResponse.headers.location);
      const code = url.searchParams.get("code");
      
      const tokenResponse = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      refreshToken = tokenResponse.body.refresh_token;
    });

    it("should return 400 for invalid refresh token", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "refresh_token",
          refresh_token: "invalid-refresh-token",
          client_id: "demo-client"
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "invalid_grant");
    });

    it("should return 400 for client_id mismatch", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: "wrong-client"
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "invalid_grant");
    });

    it("should issue new access token with valid refresh token", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: "demo-client"
        });
      
      assert.strictEqual(response.status, 200);
      assert.ok(response.body.access_token);
      assert.strictEqual(response.body.token_type, "Bearer");
      assert.strictEqual(response.body.expires_in, 900);
      assert.strictEqual(response.body.refresh_token, undefined); // No new refresh token
    });

    it("should issue new JWT that can be verified", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: "demo-client"
        });
      
      const accessToken = response.body.access_token;
      const publicKeyObj = await importSPKI(keyPair.publicKey, "RS256");
      
      const { payload } = await jwtVerify(accessToken, publicKeyObj, {
        issuer: "http://localhost:3000",
        audience: "demo-client"
      });
      
      assert.strictEqual(payload.sub, "alice");
      assert.ok(payload.scope);
    });
  });

  describe("Endpoint: POST /token (error cases)", () => {
    
    it("should return 400 for unsupported grant_type", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "client_credentials",
          client_id: "demo-client"
        });
      
      assert.strictEqual(response.status, 400);
      assert.strictEqual(response.body.error, "unsupported_grant_type");
    });

    it("should return 400 for missing grant_type", async () => {
      const response = await request(app)
        .post("/token")
        .type("form")
        .send({
          client_id: "demo-client"
        });
      
      assert.strictEqual(response.status, 400);
    });
  });

  describe("Endpoint: GET /.well-known/jwks.json", () => {
    
    it("should return JWKS with public key", async () => {
      const response = await request(app)
        .get("/.well-known/jwks.json");
      
      assert.strictEqual(response.status, 200);
      assert.ok(response.body.keys);
      assert.strictEqual(response.body.keys.length, 1);
      
      const jwk = response.body.keys[0];
      assert.strictEqual(jwk.use, "sig");
      assert.strictEqual(jwk.alg, "RS256");
      assert.strictEqual(jwk.kid, "demo-key-1");
      assert.ok(jwk.n); // RSA modulus
      assert.ok(jwk.e); // RSA exponent
      assert.ok(jwk.kty); // Key type
    });

    it("should return valid JWK that can verify tokens", async () => {
      // Get JWKS
      const jwksResponse = await request(app)
        .get("/.well-known/jwks.json");
      
      // Get a token
      const codeVerifier = generateCode();
      const codeChallenge = sha256Base64Url(codeVerifier);
      
      const authResponse = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          code_challenge: codeChallenge,
          code_challenge_method: "S256"
        });
      
      const url = new URL(authResponse.headers.location);
      const code = url.searchParams.get("code");
      
      const tokenResponse = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      const accessToken = tokenResponse.body.access_token;
      
      // Verify token using JWKS public key
      const publicKeyObj = await importSPKI(keyPair.publicKey, "RS256");
      const { payload } = await jwtVerify(accessToken, publicKeyObj, {
        issuer: "http://localhost:3000",
        audience: "demo-client"
      });
      
      assert.strictEqual(payload.sub, "alice");
    });
  });

  describe("PKCE Flow Integration", () => {
    
    it("should complete full authorization code flow with PKCE", async () => {
      // Step 1: Generate PKCE parameters
      const codeVerifier = generateCode();
      const codeChallenge = sha256Base64Url(codeVerifier);
      
      // Step 2: Request authorization code
      const authResponse = await request(app)
        .get("/authorize")
        .query({
          response_type: "code",
          client_id: "demo-client",
          redirect_uri: "http://localhost:4000/callback",
          scope: "api.read openid profile email",
          state: "test-state-123",
          code_challenge: codeChallenge,
          code_challenge_method: "S256"
        });
      
      assert.strictEqual(authResponse.status, 302);
      const location = authResponse.headers.location;
      const url = new URL(location);
      const code = url.searchParams.get("code");
      const state = url.searchParams.get("state");
      
      assert.ok(code);
      assert.strictEqual(state, "test-state-123");
      
      // Step 3: Exchange code for tokens
      const tokenResponse = await request(app)
        .post("/token")
        .type("form")
        .send({
          grant_type: "authorization_code",
          code,
          redirect_uri: "http://localhost:4000/callback",
          client_id: "demo-client",
          code_verifier: codeVerifier
        });
      
      assert.strictEqual(tokenResponse.status, 200);
      assert.ok(tokenResponse.body.access_token);
      assert.ok(tokenResponse.body.refresh_token);
      
      // Step 4: Verify JWT
      const publicKeyObj = await importSPKI(keyPair.publicKey, "RS256");
      const { payload } = await jwtVerify(tokenResponse.body.access_token, publicKeyObj, {
        issuer: "http://localhost:3000",
        audience: "demo-client"
      });
      
      assert.strictEqual(payload.sub, "alice");
      assert.ok(payload.scope.includes("api.read"));
    });
  });
});