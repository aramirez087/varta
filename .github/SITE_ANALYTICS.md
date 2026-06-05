# Site analytics (varta.sh)

The deploy workflow injects a privacy-friendly analytics snippet into every
published HTML page (landing page and mdBook).

## Default

If no secrets are configured, deploy injects the site-specific Plausible
snippet from [`scripts/plausible-snippet.html`](../scripts/plausible-snippet.html)
(loaded on every landing page and mdBook HTML file). Update that file if
Plausible rotates your `pa-*.js` script URL.

## Optional overrides (GitHub repository secrets)

| Secret | Effect |
|--------|--------|
| `CLOUDFLARE_BEACON_TOKEN` | Cloudflare Web Analytics beacon (takes precedence) |
| `PLAUSIBLE_DOMAIN` | Plausible custom domain (e.g. `varta.sh`) |

## Local preview

```bash
chmod +x scripts/inject-analytics.sh
CLOUDFLARE_BEACON_TOKEN=your-token ./scripts/inject-analytics.sh _site
```

Injection points:

- Landing page: `<!-- varta:analytics -->` in `index.html`
- mdBook pages: snippet inserted before `</head>` on deploy