import { describe, it, before, beforeEach, mock } from "node:test";
import assert from "node:assert";
import request from "supertest";
import axios from "axios";
import {
  createApp,
  base64url,
  generateVerifier,
  codeChallengeS256,
  generateState,
} from "./app.js";

/**
 * Test suite for OAuth 2.0 Client Application
 *
 * These tests verify the client application's OAuth flow implementation
 * using mocked external dependencies (axios, authorization server).
 *
 * Tests use:
 * - Node.js native test runner (node:test)
 * - Native mocking (mock.method)
 * - Supertest for HTTP testing
 */

describe("OAuth 2.0 Client Application Tests", () => {
  let app;

  before(() => {
    app = createApp();
  });

  describe("Helper Functions", () => {
    it("should generate base64url encoded strings without special characters", () => {
      const input = Buffer.from("hello+world/test=");
      const result = base64url(input);

      assert.strictEqual(result.includes("+"), false, "Should not contain +");
      assert.strictEqual(result.includes("/"), false, "Should not contain /");
      assert.strictEqual(result.includes("="), false, "Should not contain =");
    });

    it("should generate random code verifiers", () => {
      const verifier1 = generateVerifier();
      const verifier2 = generateVerifier();

      assert.strictEqual(typeof verifier1, "string");
      assert.strictEqual(typeof verifier2, "string");
      assert.notStrictEqual(verifier1, verifier2);
      assert.ok(verifier1.length >= 43);
    });

    it("should generate deterministic code challenge from verifier", () => {
      const verifier = "test-verifier-123";
      const challenge1 = codeChallengeS256(verifier);
      const challenge2 = codeChallengeS256(verifier);

      assert.strictEqual(challenge1, challenge2);
      assert.strictEqual(typeof challenge1, "string");
    });

    it("should generate random state values", () => {
      const state1 = generateState();
      const state2 = generateState();

      assert.notStrictEqual(state1, state2);
      assert.strictEqual(typeof state1, "string");
    });
  });

  describe("Route: GET /", () => {
    it("should return home page with 200 status", async () => {
      const response = await request(app).get("/");

      assert.strictEqual(response.status, 200);
      assert.ok(response.text.includes("OAuth 2.0"));
      assert.ok(response.text.includes("Login"));
    });
  });

  describe("Route: GET /login", () => {
    it("should redirect to authorization server with correct parameters", async () => {
      const response = await request(app).get("/login").expect(302);

      const location = response.headers.location;
      assert.ok(location.startsWith("http://localhost:3000/authorize"));

      const url = new URL(location);
      assert.strictEqual(url.searchParams.get("response_type"), "code");
      assert.strictEqual(url.searchParams.get("client_id"), "demo-client");
      assert.strictEqual(
        url.searchParams.get("redirect_uri"),
        "http://localhost:4000/callback"
      );
      assert.strictEqual(url.searchParams.get("code_challenge_method"), "S256");
      assert.ok(url.searchParams.get("code_challenge"));
      assert.ok(url.searchParams.get("state"));
    });

    it("should set httpOnly cookies for code_verifier and oauth_state", async () => {
      const response = await request(app).get("/login");

      const cookies = response.headers["set-cookie"];
      assert.ok(cookies);

      const hasCookieVerifier = cookies.some((c) =>
        c.startsWith("code_verifier=")
      );
      const hasCookieState = cookies.some((c) => c.startsWith("oauth_state="));

      assert.ok(hasCookieVerifier);
      assert.ok(hasCookieState);
      assert.ok(cookies.every((c) => c.includes("HttpOnly")));
    });

    it("should include all required OAuth scopes", async () => {
      const response = await request(app).get("/login");
      const location = response.headers.location;
      const url = new URL(location);
      const scope = url.searchParams.get("scope");

      assert.ok(scope.includes("api.read"));
      assert.ok(scope.includes("openid"));
      assert.ok(scope.includes("profile"));
      assert.ok(scope.includes("email"));
    });

    it("should generate unique PKCE parameters on each request", async () => {
      const response1 = await request(app).get("/login");
      const response2 = await request(app).get("/login");

      const url1 = new URL(response1.headers.location);
      const url2 = new URL(response2.headers.location);

      const state1 = url1.searchParams.get("state");
      const state2 = url2.searchParams.get("state");

      const challenge1 = url1.searchParams.get("code_challenge");
      const challenge2 = url2.searchParams.get("code_challenge");

      assert.notStrictEqual(state1, state2);
      assert.notStrictEqual(challenge1, challenge2);
    });
  });

  describe("Route: GET /callback", () => {
    it("should return 400 if authorization code is missing", async () => {
      const response = await request(app)
        .get("/callback?state=test-state")
        .set("Cookie", ["oauth_state=test-state"]);

      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("Missing authorization code"));
    });

    it("should return 400 if state parameter is invalid (CSRF protection)", async () => {
      const response = await request(app)
        .get("/callback?code=test-code&state=wrong-state")
        .set("Cookie", ["oauth_state=correct-state"]);

      assert.strictEqual(response.status, 400);
      assert.ok(response.text.includes("Invalid state"));
    });

    it("should exchange code for tokens successfully with mocked axios", async () => {
      // Mock axios.post for token exchange
      const mockPost = mock.method(axios, "post", () => {
        return Promise.resolve({
          data: {
            access_token: "mock-access-token-abc123",
            refresh_token: "mock-refresh-token-xyz789",
            expires_in: 900,
            token_type: "Bearer",
          },
        });
      });

      const testState = "test-state-12345";
      const response = await request(app)
        .get(`/callback?code=auth-code-789&state=${testState}`)
        .set("Cookie", [
          `oauth_state=${testState}`,
          `code_verifier=test-verifier-abc`,
        ]);

      assert.strictEqual(response.status, 200);
      assert.ok(response.text.includes("Logged in!"));
      assert.ok(response.text.includes("900 seconds"));

      // Verify axios was called with correct parameters
      assert.strictEqual(mockPost.mock.calls.length, 1);
      const [url, body, config] = mockPost.mock.calls[0].arguments;

      assert.strictEqual(url, "http://localhost:3000/token");
      assert.ok(body.includes("grant_type=authorization_code"));
      assert.ok(body.includes("code=auth-code-789"));
      assert.ok(body.includes("code_verifier=test-verifier-abc"));
      assert.strictEqual(
        config.headers["Content-Type"],
        "application/x-www-form-urlencoded"
      );

      // Verify cookies are set
      const cookies = response.headers["set-cookie"];
      assert.ok(
        cookies.some((c) =>
          c.startsWith("access_token=mock-access-token-abc123")
        )
      );
      assert.ok(
        cookies.some((c) =>
          c.startsWith("refresh_token=mock-refresh-token-xyz789")
        )
      );

      mockPost.mock.restore();
    });

    it("should handle token exchange errors gracefully", async () => {
      // Mock axios.post to simulate network error
      const mockPost = mock.method(axios, "post", () => {
        return Promise.reject(new Error("Network error"));
      });

      const testState = "test-state-error";
      const response = await request(app)
        .get(`/callback?code=test-code&state=${testState}`)
        .set("Cookie", [
          `oauth_state=${testState}`,
          `code_verifier=test-verifier`,
        ]);

      assert.strictEqual(response.status, 500);
      assert.ok(response.text.includes("Token exchange failed"));

      mockPost.mock.restore();
    });

    it("should clear OAuth-only cookies after successful token exchange", async () => {
      const mockPost = mock.method(axios, "post", () => {
        return Promise.resolve({
          data: {
            access_token: "token",
            refresh_token: "refresh",
            expires_in: 900,
          },
        });
      });

      const testState = "state-123";
      const response = await request(app)
        .get(`/callback?code=code-123&state=${testState}`)
        .set("Cookie", [
          `oauth_state=${testState}`,
          `code_verifier=verifier-123`,
        ]);

      const setCookies = response.headers["set-cookie"];

      // Should clear oauth_state and code_verifier
      const clearsVerifier = setCookies.some(
        (c) => c.startsWith("code_verifier=") && c.includes("Expires=")
      );
      const clearsState = setCookies.some(
        (c) => c.startsWith("oauth_state=") && c.includes("Expires=")
      );

      assert.ok(clearsVerifier || clearsState, "Should clear OAuth cookies");

      mockPost.mock.restore();
    });
  });

  describe("Route: GET /profile", () => {
    it("should redirect to home if no access token", async () => {
      const response = await request(app).get("/profile");

      assert.strictEqual(response.status, 302);
      assert.strictEqual(response.headers.location, "/");
    });

    it("should call protected API with access token using mocked axios", async () => {
      // Mock axios.get for API call
      const mockGet = mock.method(axios, "get", () => {
        return Promise.resolve({
          data: {
            message: "Protected profile data",
            user: {
              sub: "alice",
              name: "Alice Example",
              email: "alice@example.com",
              scope: "api.read openid profile email",
            },
          },
        });
      });

      const response = await request(app)
        .get("/profile")
        .set("Cookie", ["access_token=mock-jwt-token-12345"]);

      assert.strictEqual(response.status, 200);
      assert.ok(response.text.includes("Protected profile data"));
      assert.ok(response.text.includes("alice@example.com"));

      // Verify axios was called correctly
      assert.strictEqual(mockGet.mock.calls.length, 1);
      const [url, config] = mockGet.mock.calls[0].arguments;

      assert.strictEqual(url, "http://localhost:5000/api/profile");
      assert.strictEqual(
        config.headers.Authorization,
        "Bearer mock-jwt-token-12345"
      );

      mockGet.mock.restore();
    });

    it("should handle API errors gracefully", async () => {
      // Mock axios.get to simulate API error
      const mockGet = mock.method(axios, "get", () => {
        const error = new Error("API unavailable");
        error.response = { data: { error: "service_unavailable" } };
        return Promise.reject(error);
      });

      const response = await request(app)
        .get("/profile")
        .set("Cookie", ["access_token=mock-token"]);

      assert.strictEqual(response.status, 500);
      assert.ok(response.text.includes("API call failed"));

      mockGet.mock.restore();
    });
  });

  describe("Route: GET /refresh", () => {
    it("should redirect to home if no refresh token", async () => {
      const response = await request(app).get("/refresh");

      assert.strictEqual(response.status, 302);
      assert.strictEqual(response.headers.location, "/");
    });

    it("should refresh access token successfully with mocked axios", async () => {
      // Mock axios.post for token refresh
      const mockPost = mock.method(axios, "post", () => {
        return Promise.resolve({
          data: {
            access_token: "new-access-token-xyz",
            token_type: "Bearer",
            expires_in: 900,
          },
        });
      });

      const response = await request(app)
        .get("/refresh")
        .set("Cookie", ["refresh_token=valid-refresh-token-abc"]);

      assert.strictEqual(response.status, 200);
      assert.ok(response.text.includes("Refreshed Access Token!"));
      assert.ok(response.text.includes("900 seconds"));

      // Verify new access token cookie is set
      const cookies = response.headers["set-cookie"];
      assert.ok(
        cookies.some((c) => c.startsWith("access_token=new-access-token-xyz"))
      );

      // Verify axios was called with correct grant type
      assert.strictEqual(mockPost.mock.calls.length, 1);
      const [url, body] = mockPost.mock.calls[0].arguments;

      assert.strictEqual(url, "http://localhost:3000/token");
      assert.ok(body.includes("grant_type=refresh_token"));
      assert.ok(body.includes("refresh_token=valid-refresh-token-abc"));
      assert.ok(body.includes("client_id=demo-client"));

      mockPost.mock.restore();
    });

    it("should handle refresh errors gracefully", async () => {
      // Mock axios.post to simulate invalid refresh token
      const mockPost = mock.method(axios, "post", () => {
        const error = new Error("Invalid refresh token");
        error.response = { data: { error: "invalid_grant" } };
        return Promise.reject(error);
      });

      const response = await request(app)
        .get("/refresh")
        .set("Cookie", ["refresh_token=expired-token"]);

      assert.strictEqual(response.status, 500);
      assert.ok(response.text.includes("Token refresh failed"));

      mockPost.mock.restore();
    });
  });

  describe("PKCE Flow Integration", () => {
    it("should complete full OAuth flow with PKCE validation", async () => {
      // Step 1: Initiate login
      const loginResponse = await request(app).get("/login");
      const cookies = loginResponse.headers["set-cookie"];
      const location = loginResponse.headers.location;
      const url = new URL(location);
      const state = url.searchParams.get("state");
      const codeChallenge = url.searchParams.get("code_challenge");

      assert.ok(state);
      assert.ok(codeChallenge);

      // Step 2: Mock token exchange with PKCE verification
      const mockPost = mock.method(axios, "post", (url, body) => {
        // Verify PKCE parameters are sent
        assert.ok(body.includes("code_verifier="));

        return Promise.resolve({
          data: {
            access_token: "integration-test-token",
            refresh_token: "integration-refresh-token",
            expires_in: 900,
          },
        });
      });

      // Step 3: Complete callback
      const callbackResponse = await request(app)
        .get(`/callback?code=auth-code-integration&state=${state}`)
        .set(
          "Cookie",
          cookies.map((c) => c.split(";")[0])
        );

      assert.strictEqual(callbackResponse.status, 200);

      // Step 4: Verify tokens are stored
      const tokenCookies = callbackResponse.headers["set-cookie"];
      assert.ok(tokenCookies.some((c) => c.startsWith("access_token=")));
      assert.ok(tokenCookies.some((c) => c.startsWith("refresh_token=")));

      mockPost.mock.restore();
    });
  });
});
