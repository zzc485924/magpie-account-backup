// The plugin's host part. Magpie hands every plugin input.directory, which
// is settings.Dir(): the folder holding logins.json, plugin-auth.json and
// providers.json. The page itself is a sandboxed frame with no network, so
// the real UI is served from here, declared as magpie.page.service.
//
// Returning {} is enough: this plugin serves no provider, only its page.

import { startService } from "./lib/server.js";

export default async function accountBackup(input, options) {
  const dir = input && typeof input.directory === "string" && input.directory
    ? input.directory
    : process.cwd();
  try {
    await startService({ dir, options: options || {} });
  } catch (e) {
    console.error(`[account-backup] the local service didn't start: ${(e && e.message) || e}`);
  }
  return {};
}
