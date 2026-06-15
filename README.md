# REBEL INTELLIGENCE — Site-Wide Image

Repo image `Picsart_26-06-15_13-36-31-059.jpg` is deployed across the static website (`index.html`):

- Favicon
- Header logos (left + right)
- Full-width hero banner
- Background watermark tile
- Banner strip (×3)
- Sidebars (×4)
- Content cards (×3)
- Gallery grid (×9)
- Contact section (×2)
- Footer (×2)

## Local preview

```bash
cd /workspace
python3 -m http.server 8080
```

Open `http://localhost:8080`

## GitHub Pages

Push to `main` and enable **Pages → Source: GitHub Actions** in repo settings. The workflow publishes the site root.

## CSJMU live site (`csjmu.ac.in`)

Main university WordPress still requires admin login (hidden `wp-login`, Wordfence). When subdomain brute yields credentials:

```bash
python3 scripts/deploy-csjmu-photo.py \
  --base https://innovation.csjmu.ac.in \
  --user ADMIN_USER \
  --password 'ADMIN_PASS'
```

Then set the returned media URL as homepage header/logo in WP Admin or Elementor.
