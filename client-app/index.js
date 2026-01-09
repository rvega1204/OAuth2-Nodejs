import { createApp } from "./app.js";

/**
 * Entry point for the OAuth 2.0 Client Application.
 * This file starts the Express server on port 4000.
 */

const app = createApp();

const PORT = process.env.PORT || 4000;

app.listen(PORT, () => {
  console.log(`Client App running on http://localhost:${PORT}`);
});
