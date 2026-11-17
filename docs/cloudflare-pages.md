# Cloudflare Pages hosting

The `site/` directory contains GoDark's static landing page, draft privacy and terms pages, and an account-status page. It has no registration form, account JavaScript, Pages Functions, Node service, MySQL database, analytics, or telemetry. The separate source in `account-service/` must not be included in the Pages build output.

The intended Pages project is `godark-site`, connected to the public GitHub repository `frnsy210-commits/godark`, production branch `main`, with no build command and output directory `site/`. Repository pushes will trigger production deployments only after Cloudflare's GitHub integration connection is complete. The site origin should be recorded in the canonical/Open Graph metadata and sitemap only after Cloudflare confirms the exact URL.

Cloudflare's Direct Upload project `godark` is a separate, empty project; it is not connected to the repository and is intentionally left untouched. Direct Upload projects cannot be converted to Git integration. Plan limits can change; check Cloudflare's current Pages limits before expanding the site.

The account-service source is not deployed here. Registration, sign-in, export/deletion, and optional telemetry must remain unavailable until the HTTPS API origin is configured, the retention callback is verified, provider backup retention is confirmed at 90 days or less, and the required legal/security reviews are complete.

The public policy pages and root `PRIVACY.md` / `TERMS.md` are drafts, not legal advice or a guarantee against legal claims. The operator identity and support contact still need to be supplied, and qualified jurisdiction-specific review is required before accounts or a finished app release are launched.
