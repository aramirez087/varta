#!/usr/bin/env bash
# Emit sitemap.xml for all deployed HTML (landing page + mdBook).
set -euo pipefail

SITE_ROOT="${1:-_site}"
OUT="${2:-${SITE_ROOT}/sitemap.xml}"
BASE="https://varta.sh"
TODAY="$(date -u +%Y-%m-%d)"

{
  echo '<?xml version="1.0" encoding="UTF-8"?>'
  echo '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">'

  while IFS= read -r -d '' file; do
    rel="${file#"${SITE_ROOT}"}"
    # install.sh redirect stub — not indexable content
    [[ "${rel}" == */install.sh/* ]] && continue

    if [[ "$(basename "${file}")" == "index.html" ]]; then
      path="${rel%/index.html}"
      if [[ -z "${path}" ]]; then
        loc="${BASE}/"
        priority="1.0"
      else
        loc="${BASE}${path}/"
        priority="0.8"
      fi
    else
      loc="${BASE}${rel}"
      priority="0.6"
    fi

    echo "  <url>"
    echo "    <loc>${loc}</loc>"
    echo "    <lastmod>${TODAY}</lastmod>"
    echo "    <changefreq>weekly</changefreq>"
    echo "    <priority>${priority}</priority>"
    echo "  </url>"
  done < <(find "${SITE_ROOT}" -name '*.html' -print0 | sort -z)

  echo '</urlset>'
} > "${OUT}"

count="$(grep -c '<loc>' "${OUT}" || true)"
echo "generate-sitemap: ${count} URLs -> ${OUT}"