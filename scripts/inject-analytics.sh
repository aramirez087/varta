#!/usr/bin/env bash
set -euo pipefail

SITE_ROOT="${1:-_site}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PLAUSIBLE_SNIPPET="${SCRIPT_DIR}/plausible-snippet.html"
PLAUSIBLE_ID="pa-YyA03_Ow6U040l0wzUwht"

export SITE_ROOT
export PLAUSIBLE_ID

if [[ -n "${CLOUDFLARE_BEACON_TOKEN:-}" ]]; then
  export SNIPPET_SOURCE=env
  export SNIPPET='<script defer src="https://static.cloudflareinsights.com/beacon.min.js" data-cf-beacon='"'"'{"token":"'"${CLOUDFLARE_BEACON_TOKEN}"'"}'"'"'></script>'
elif [[ -n "${PLAUSIBLE_DOMAIN:-}" ]]; then
  export SNIPPET_SOURCE=env
  export SNIPPET="<script defer data-domain=\"${PLAUSIBLE_DOMAIN}\" src=\"https://plausible.io/js/script.js\"></script>"
else
  export SNIPPET_SOURCE=file
  export PLAUSIBLE_SNIPPET
fi

python3 <<'PY'
import os
from pathlib import Path

root = Path(os.environ["SITE_ROOT"])
marker = "<!-- varta:analytics -->"
plausible_id = os.environ["PLAUSIBLE_ID"]

if os.environ.get("SNIPPET_SOURCE") == "file":
    snippet = Path(os.environ["PLAUSIBLE_SNIPPET"]).read_text(encoding="utf-8").strip()
else:
    snippet = os.environ["SNIPPET"].strip()

updated = 0
for path in root.rglob("*.html"):
    text = path.read_text(encoding="utf-8")
    if plausible_id in text:
        continue
    if marker in text:
        path.write_text(text.replace(marker, marker + "\n" + snippet, 1), encoding="utf-8")
        updated += 1
        continue
    if "</head>" in text:
        path.write_text(text.replace("</head>", snippet + "\n</head>", 1), encoding="utf-8")
        updated += 1

print(f"inject-analytics: updated {updated} HTML file(s) under {root}")
PY