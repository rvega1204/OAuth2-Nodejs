/**
 * Entry point for the OAuth 2.0 Resource Server.
 * This file starts the Express server on port 5000.
 */

import { createApp } from "./app.js";

const app = createApp();

const PORT = process.env.PORT || 5000;

app.listen(PORT, () => {
  console.log(`Resource Server running on http://localhost:${PORT}`);
});