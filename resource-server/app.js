/**
 * Resource Server - OAuth 2.0 Protected API
 * 
 * This module implements a resource server that validates JWT tokens issued by an OAuth 2.0
 * authorization server and provides protected endpoints with scope-based access control.
 * 
 * @module resource-server
 * @requires express
 * @requires jose
 */

import express from "express";
import { jwtVerify, createRemoteJWKSet } from "jose";

const ISSUER = process.env.ISSUER || "http://localhost:3000";
const AUDIENCE = process.env.AUDIENCE || "demo-client";
const JWKS_URL = process.env.JWKS_URL || "http://localhost:3000/.well-known/jwks.json";

/**
 * Middleware to authenticate requests using JWT Bearer tokens.
 * 
 * Validates the JWT token against the JWKS (JSON Web Key Set) from the authorization server,
 * verifying the issuer and audience claims.
 * 
 * @async
 * @function requireAuth
 * @param {Object} req - Express request object
 * @param {Object} req.headers - Request headers
 * @param {string} req.headers.authorization - Bearer token in format "Bearer <token>"
 * @param {Object} res - Express response object
 * @param {Function} next - Express next middleware function
 * @returns {void}
 * @throws {Error} Returns 401 if token is missing or invalid
 */
export async function requireAuth(req, res, next) {
  const JWKS = createRemoteJWKSet(new URL(JWKS_URL));
  
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith("Bearer ")) {
    return res.status(401).json({ error: "missing_token" });
  }

  const token = auth.slice("Bearer ".length);
  try {
    const { payload } = await jwtVerify(token, JWKS, {
      issuer: ISSUER,
      audience: AUDIENCE,
    });

    req.user = payload;
    next();
  } catch (error) {
    return res.status(401).json({ 
      error: "invalid_token", 
      message: error.message 
    });
  }
}

/**
 * Higher-order middleware factory to enforce scope-based access control.
 * 
 * Verifies that the authenticated user's token includes the required scope.
 * 
 * @function requireScope
 * @param {string} scope - The required scope to access the resource
 * @returns {Function} Express middleware function
 * @throws {Error} Returns 403 Forbidden if required scope is not present
 */
export function requireScope(scope) {
  return (req, res, next) => {
    const scopes = String(req.user?.scope || "").split(" ").filter(Boolean);
    if (!scopes.includes(scope)) {
      return res.status(403).json({ 
        error: "insufficient_scope", 
        required: scope 
      });
    }

    next();
  };
}

/**
 * Creates and configures the Express application for the resource server.
 * Exported as a function to allow testing without starting the server.
 * 
 * @returns {express.Application} Configured Express app
 */
export function createApp() {
  const app = express();
  app.use(express.json());

  /**
   * GET /api/profile
   * 
   * Protected endpoint that returns user profile information.
   * Requires authentication and 'api.read' scope.
   * 
   * @route GET /api/profile
   * @middleware requireAuth - JWT authentication required
   * @middleware requireScope('api.read') - User must have api.read scope
   * @returns {Object} User profile data including sub, name, email, and granted scopes
   * @returns {number} 200 - Success
   * @returns {number} 401 - Missing or invalid token
   * @returns {number} 403 - Insufficient scope
   */
  app.get("/api/profile", requireAuth, requireScope("api.read"), (req, res) => {
    res.json({
      message: "Protected profile data",
      user: {
        sub: req.user.sub,
        name: req.user.name,
        email: req.user.email,
        scope: req.user.scope
      }
    });
  });

  /**
   * GET /health
   * 
   * Health check endpoint (unprotected).
   * Used to verify the server is running.
   * 
   * @route GET /health
   * @returns {Object} Server status
   * @returns {number} 200 - Server is healthy
   */
  app.get("/health", (req, res) => {
    res.json({ status: "ok", service: "resource-server" });
  });

  return app;
}