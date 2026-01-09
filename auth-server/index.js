/**
 * Entry point for the OAuth 2.0 Authorization Server.
 * This file starts the Express server on port 3000.
 */

import { createApp } from "./app.js";

const { app } = createApp();

const PORT = process.env.PORT || 3000;

app.listen(PORT, () => {
  console.log(`Auth Server running on http://localhost:${PORT}`);
});