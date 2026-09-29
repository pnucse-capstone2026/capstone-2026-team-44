# DemoShop presentation assets

Four original product mockups were generated on 2026-09-13 using the built-in
ImageGen tool and copied byte-for-byte as PNG files. No third-party image host,
font CDN, runtime dependency or real product endorsement is involved. The
fictional names/prices are presentation data in `demo_shop_storefront.py`.

## Prompt set

All prompts requested a square, editorial ecommerce studio photograph for a
Korean lifestyle demo storefront, with realistic materials, soft directional
light, full product framing, and no text, logos or watermarks.

- `sneakers.png`: Premium unbranded ivory/sand suede everyday sneakers with a
  sculptural gum sole, three-quarter view, one shoe behind the other, warm pale
  seamless sand floor, morning light, realistic stitching, room around product.
- `tote.png`: Premium natural oatmeal canvas tote with dark brown leather handles,
  upright three-quarter view, warm off-white studio, realistic textile texture.
- `headphones.png`: Matte graphite over-ear headphones with a soft padded headband,
  three-quarter view, warm grey seamless studio, tactile material and soft light.
- `lamp.png`: Sculptural terracotta mushroom lamp with a broad rounded dome and
  short cylindrical base, gently lit, cream studio, matte powder-coated finish.

Only the exact routes in `demo_shop_storefront.ASSETS` are served. Incoming
URL paths are never joined to a filesystem directory. CSS and JS are external
local assets so their size does not inflate each probe's HTML response body.

## Colour variants

The catalog is twelve products over these four photos. The eight
`*-<colour>.jpg` files (1024px, ~70–125 KB each) were derived on 2026-09-16 by
`make_variants.py` in this directory. The product matte comes from `rembg`
(U²-Net; ISNet for the tote so its handle loops stay open) — a learned
segmentation that leaves the studio floor, the cast shadows and the product's
own highlights untouched, which GrabCut could not. Only the product is then
recoloured with its shading kept: darkened for black, colourised for navy /
blue / sage / cream, lightened for silver, pulled to white in Lab for the
white sneakers; both sneaker colourways keep the photographed gum sole.

Regenerate from the PNGs in an isolated environment (the model files are
fetched to `~/.rembg` on first use, ~180 MB each; none of this is a DemoShop
runtime dependency):

    python -m venv .venv-assets
    .venv-assets/Scripts/pip install "rembg[cpu]" opencv-python-headless
    .venv-assets/Scripts/python tools/demo_shop_assets/make_variants.py

`demo_shop_storefront.PRODUCTS` maps each product to its file.

Product/category selections and quantities use bounded URL fragments and DOM
updates. Orders are a local visual simulation; no payment, persistence, remote
API calls or state-changing requests are implemented. The canonical GET forms,
seeds and vulnerability fragments remain the evaluation surface: each route's
form is laid out by `demo_shop_storefront.route_body` as the page's own filter
bar, option panel or service form, and `shop.js` filters, sorts and pages the
server-rendered grid from the URL query. Chips, pager and tab buttons are
unnamed `type="button"` controls; the catalog reaches the page as a JSON
`<script type="application/json">` block.

The header search box is a bare `<input type="search">` with no `name` and no
`<form>`: `shop.js` turns Enter or the magnifier into `/search?q=<term>`, which
is the canonical form's first input point, and narrows the product grid on the
client. Reveal mode (`html.reveal-inputs`, toggled by the fixed pill and kept in
`localStorage` under `demoshop-reveal-inputs`) is CSS-only emphasis: outlines and
number badges on the canonical controls, and static `⊙ #NNN label name` tags on
the storefront controls that feed one of them. Tags are rendered by
`demo_shop._input_of` from `INPUT_POINT_NUMBERS`, never by the storefront module.

The storefront HTML and recommendation images change response-size baselines.
Historical ranking metrics should not be compared as if the target bytes were
unchanged; rerun evaluation and record the target revision for comparisons.
