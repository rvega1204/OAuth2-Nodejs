import express from "express";
import cookieParser from "cookie-parser";
import { randomBytes, createHash } from "crypto";
import axios from "axios";

/**
 * OAuth 2.0 Client implementation with PKCE (Proof Key for Code Exchange).
 *
 * This module handles the client-side logic for the authorization flow,
 * including state management, PKCE challenge generation, and interaction
 * with the authorization and resource servers.
 */

const AUTH_SERVER = process.env.AUTH_SERVER || "http://localhost:3000";
const RESOURCE_SERVER = process.env.RESOURCE_SERVER || "http://localhost:5000";
const CLIENT_ID = process.env.CLIENT_ID || "demo-client";
const REDIRECT_URI =
  process.env.REDIRECT_URI || "http://localhost:4000/callback";

/**
 * Converts a Buffer to a base64url-encoded string.
 * Base64url encoding is URL-safe (replaces +/= with -_).
 *
 * @param {Buffer} input - The buffer to encode
 * @returns {string} Base64url-encoded string
 */
export function base64url(input) {
  return input
    .toString("base64")
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
}

/**
 * Generates a cryptographically random code verifier for PKCE.
 *
 * @returns {string} A random code verifier (base64url-encoded)
 */
export function generateVerifier() {
  return base64url(randomBytes(32));
}

/**
 * Generates a code challenge using the S256 method (SHA-256).
 * This is sent to the authorization server during the initial request.
 *
 * @param {string} verifier - The code verifier to hash
 * @returns {string} The SHA-256 code challenge (base64url-encoded)
 */
export function codeChallengeS256(verifier) {
  const hash = createHash("sha256").update(verifier).digest();
  return base64url(hash);
}

/**
 * Generates a random state parameter for CSRF protection.
 *
 * @returns {string} A random state value (base64url-encoded)
 */
export function generateState() {
  return base64url(randomBytes(16));
}

/**
 * Creates and configures the Express application.
 * Exported as a function to allow testing without starting the server.
 *
 * @returns {express.Application} Configured Express app
 */
export function createApp() {
  const app = express();
  app.use(cookieParser());

  /**
   * Home page route.
   * Displays the landing page with a login button.
   *
   * @route GET /
   */
  app.get("/", (req, res) => {
    res.send(`
      <!DOCTYPE html>
      <html>
      <head>
        <title>OAuth 2.0 Client App</title>
        <style>
          body {
            font-family: Arial, sans-serif;
            max-width: 600px;
            margin: 50px auto;
            padding: 20px;
            background-color: #f5f5f5;
          }
          .container {
            background-color: white;
            padding: 40px;
            border-radius: 10px;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
          }
          h1 {
            color: #2c3e50;
            margin-top: 0;
          }
          p {
            color: #7f8c8d;
            font-size: 16px;
            line-height: 1.6;
          }
          .info-box {
            background-color: #e8f4f8;
            border-left: 4px solid #3498db;
            padding: 15px;
            margin: 20px 0;
            border-radius: 4px;
          }
          .info-box strong {
            color: #2980b9;
          }
          a {
            display: inline-block;
            margin-top: 20px;
            padding: 15px 30px;
            background-color: #3498db;
            color: white;
            text-decoration: none;
            border-radius: 5px;
            font-size: 18px;
            font-weight: bold;
            transition: background-color 0.3s;
          }
          a:hover {
            background-color: #2980b9;
          }
        </style>
      </head>
      <body>
        <div class="container">
          <h1>🔐 OAuth 2.0 Client App</h1>
          <p>Welcome to the OAuth 2.0 demo application.</p>
          
          <div class="info-box">
            <strong>Security:</strong> This app uses <strong>Authorization Code Flow with PKCE</strong> 
            (Proof Key for Code Exchange) to securely authenticate users.
          </div>
          
          <p>Click the button below to start the authentication process:</p>
          
          <a href="/login">Login with OAuth 2.0</a>
        </div>
      </body>
      </html>
    `);
  });

  /**
   * Login route - initiates the OAuth 2.0 authorization flow.
   *
   * Steps:
   * 1. Generates PKCE code verifier and challenge
   * 2. Generates state for CSRF protection
   * 3. Stores verifier and state in cookies
   * 4. Redirects user to authorization server
   *
   * @route GET /login
   */
  app.get("/login", (req, res) => {
    // Generate PKCE parameters
    const code_verifier = generateVerifier();
    const code_challenge = codeChallengeS256(code_verifier);
    const state = generateState();

    // Store verifier & state in httpOnly cookies (demo only)
    // In production: use server-side session store
    res.cookie("code_verifier", code_verifier, { httpOnly: true });
    res.cookie("oauth_state", state, { httpOnly: true });

    // Build authorization URL with all required parameters
    const authorizeUrl = new URL(`${AUTH_SERVER}/authorize`);
    authorizeUrl.searchParams.set("response_type", "code");
    authorizeUrl.searchParams.set("client_id", CLIENT_ID);
    authorizeUrl.searchParams.set("redirect_uri", REDIRECT_URI);
    authorizeUrl.searchParams.set("scope", "api.read openid profile email");
    authorizeUrl.searchParams.set("state", state);
    authorizeUrl.searchParams.set("code_challenge", code_challenge);
    authorizeUrl.searchParams.set("code_challenge_method", "S256");

    // Redirect to authorization server
    res.redirect(authorizeUrl.toString());
  });

  /**
   * OAuth callback route - exchanges authorization code for tokens.
   *
   * Steps:
   * 1. Validates state parameter (CSRF protection)
   * 2. Exchanges authorization code + code verifier for tokens
   * 3. Stores tokens in cookies
   * 4. Displays success page
   *
   * @route GET /callback
   * @queryparam {string} code - Authorization code from auth server
   * @queryparam {string} state - State parameter for validation
   */
  app.get("/callback", async (req, res) => {
    const { code, state } = req.query;

    // Validate authorization code is present
    if (!code) {
      return res.status(400).send("Missing authorization code");
    }

    // Validate state parameter (CSRF protection)
    if (state !== req.cookies.oauth_state) {
      return res.status(400).send("Invalid state");
    }

    const code_verifier = req.cookies.code_verifier;

    try {
      // Exchange authorization code for access token
      const tokenRes = await axios.post(
        `${AUTH_SERVER}/token`,
        new URLSearchParams({
          grant_type: "authorization_code",
          code,
          redirect_uri: REDIRECT_URI,
          client_id: CLIENT_ID,
          code_verifier, // PKCE verification
        }).toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      const { access_token, refresh_token, expires_in } = tokenRes.data;

      // Store tokens in httpOnly cookies
      res.cookie("access_token", access_token, { httpOnly: true });
      res.cookie("refresh_token", refresh_token, { httpOnly: true });

      // Clean up OAuth-only cookies
      res.clearCookie("code_verifier");
      res.clearCookie("oauth_state");

      // Display success page with token information
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Logged In</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              max-width: 600px;
              margin: 50px auto;
              padding: 20px;
            }
            h1 {
              color: #2c3e50;
            }
            .info {
              background-color: #ecf0f1;
              padding: 15px;
              border-radius: 5px;
              margin: 20px 0;
              font-size: 18px;
            }
            a {
              display: inline-block;
              margin: 10px 10px 10px 0;
              padding: 12px 24px;
              background-color: #3498db;
              color: white;
              text-decoration: none;
              border-radius: 5px;
              font-size: 16px;
            }
            a:hover {
              background-color: #2980b9;
            }
            .refresh-link {
              background-color: #27ae60;
            }
            .refresh-link:hover {
              background-color: #229954;
            }
          </style>
        </head>
        <body>
          <h1>Logged in!</h1>
          
          <div class="info">
            Access token expires in ${expires_in} seconds.
          </div>
          
          <a href="/profile">Call Protected API</a>
          <a href="/refresh" class="refresh-link">Refresh Access Token</a>
        </body>
        </html>
      `);
    } catch (err) {
      console.error("Token exchange error:", err.response?.data || err.message);
      res
        .status(500)
        .send(
          `Token exchange failed: ${JSON.stringify(
            err.response?.data || err.message
          )}`
        );
    }
  });

  /**
   * Profile route - calls the protected API endpoint.
   * Uses the access token stored in cookies to authenticate.
   *
   * @route GET /profile
   */
  app.get("/profile", async (req, res) => {
    const accessToken = req.cookies.access_token;

    // Redirect to home if not authenticated
    if (!accessToken) return res.redirect("/");

    try {
      // Call protected API with Bearer token
      const apiRes = await axios.get(`${RESOURCE_SERVER}/api/profile`, {
        headers: { Authorization: `Bearer ${accessToken}` },
      });

      // Display profile data
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Profile</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              max-width: 600px;
              margin: 50px auto;
              padding: 20px;
            }
            h2 {
              color: #2c3e50;
            }
            pre {
              background-color: #f8f9fa;
              padding: 20px;
              border-radius: 5px;
              overflow-x: auto;
            }
            a {
              display: inline-block;
              margin-top: 20px;
              padding: 10px 20px;
              background-color: #3498db;
              color: white;
              text-decoration: none;
              border-radius: 5px;
            }
            a:hover {
              background-color: #2980b9;
            }
          </style>
        </head>
        <body>
          <h2>Protected Profile Data</h2>
          <pre>${JSON.stringify(apiRes.data, null, 2)}</pre>
          <a href="/">Back to Home</a>
        </body>
        </html>
      `);
    } catch (err) {
      const msg = err?.response?.data
        ? JSON.stringify(err.response.data)
        : err.message;
      res.status(500).send(`API call failed: ${msg}`);
    }
  });

  /**
   * Refresh token route - obtains a new access token.
   * Uses the refresh token to get a new access token without re-authentication.
   *
   * @route GET /refresh
   */
  app.get("/refresh", async (req, res) => {
    const refreshToken = req.cookies.refresh_token;

    // Redirect to home if no refresh token
    if (!refreshToken) return res.redirect("/");

    try {
      // Request new access token using refresh token
      const tokenRes = await axios.post(
        `${AUTH_SERVER}/token`,
        new URLSearchParams({
          grant_type: "refresh_token",
          refresh_token: refreshToken,
          client_id: CLIENT_ID,
        }).toString(),
        { headers: { "Content-Type": "application/x-www-form-urlencoded" } }
      );

      const { access_token, expires_in } = tokenRes.data;

      // Update access token cookie
      res.cookie("access_token", access_token, { httpOnly: true });

      // Display success message
      res.send(`
        <!DOCTYPE html>
        <html>
        <head>
          <title>Token Refreshed</title>
          <style>
            body {
              font-family: Arial, sans-serif;
              max-width: 600px;
              margin: 50px auto;
              padding: 20px;
            }
            h2 {
              color: #27ae60;
            }
            .info {
              background-color: #d5f4e6;
              padding: 15px;
              border-radius: 5px;
              margin: 20px 0;
            }
            a {
              display: inline-block;
              margin: 10px 10px 10px 0;
              padding: 12px 24px;
              background-color: #3498db;
              color: white;
              text-decoration: none;
              border-radius: 5px;
            }
            a:hover {
              background-color: #2980b9;
            }
          </style>
        </head>
        <body>
          <h2>✓ Refreshed Access Token!</h2>
          <div class="info">
            New token expires in ${expires_in} seconds.
          </div>
          <a href="/profile">Call Protected API Again</a>
        </body>
        </html>
      `);
    } catch (err) {
      console.error("Token refresh error:", err.response?.data || err.message);
      res
        .status(500)
        .send(
          `Token refresh failed: ${JSON.stringify(
            err.response?.data || err.message
          )}`
        );
    }
  });

  return app;
}
