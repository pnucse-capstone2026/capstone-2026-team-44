"""Recolour only the product in the four bundled studio photos.

One-off asset generator; not a runtime dependency of DemoShop. It writes the
colour variants ``demo_shop_storefront.PRODUCTS`` reference as 1024px JPEGs::

    python -m venv .venv-assets
    .venv-assets/Scripts/pip install "rembg[cpu]" opencv-python-headless
    .venv-assets/Scripts/python tools/demo_shop_assets/make_variants.py

The product matte comes from ``rembg`` (U²-Net, ISNet for the tote; models
are fetched on first use): it separates the product from the studio floor,
its cast shadow and its own highlights cleanly, which GrabCut could not. Without
``rembg`` the script falls back to a GrabCut mask and says so. The headphones
are then gated to dark pixels and the lamp to saturated ones; the sneakers
keep their gum sole (a chroma-based band). Recolouring keeps the shading:
darken, colourise or lighten in HLS, or pull to white in Lab.
"""

from __future__ import annotations

from collections.abc import Callable
from pathlib import Path

import cv2
import numpy as np

HERE = Path(__file__).resolve().parent
SIZE = 1024
Image = np.ndarray


def load(name: str) -> Image:
    image = cv2.imread(str(HERE / f"{name}.png"))
    return cv2.resize(image, (SIZE, SIZE), interpolation=cv2.INTER_AREA)


def hls(image: Image) -> Image:
    return cv2.cvtColor(image.astype(np.float32) / 255.0, cv2.COLOR_BGR2HLS)


def hsv(image: Image) -> Image:
    return cv2.cvtColor(image.astype(np.float32) / 255.0, cv2.COLOR_BGR2HSV)


def bgr(image: Image) -> Image:
    return np.clip(cv2.cvtColor(image, cv2.COLOR_HLS2BGR) * 255.0, 0, 255).astype(np.uint8)


def largest_components(mask: Image, min_ratio: float = 0.002) -> Image:
    count, labels, stats, _ = cv2.connectedComponentsWithStats(mask)
    keep = np.zeros_like(mask)
    for index in range(1, count):
        if stats[index, cv2.CC_STAT_AREA] > min_ratio * mask.size:
            keep[labels == index] = 255
    return keep


def fill_holes(mask: Image, max_ratio: float = 0.04) -> Image:
    """Fill enclosed gaps (highlights) but keep large enclosed background."""

    inverse = cv2.bitwise_not(mask)
    count, labels, stats, _ = cv2.connectedComponentsWithStats(inverse)
    border = set(
        np.unique(np.concatenate([labels[0], labels[-1], labels[:, 0], labels[:, -1]]))
    )
    filled = mask.copy()
    for index in range(1, count):
        if index not in border and stats[index, cv2.CC_STAT_AREA] < max_ratio * mask.size:
            filled[labels == index] = 255
    return filled


def grabcut(image: Image) -> Image:
    """Fallback segmentation when rembg is not installed."""

    height, width = image.shape[:2]
    mask = np.zeros((height, width), np.uint8)
    background = np.zeros((1, 65), np.float64)
    foreground = np.zeros((1, 65), np.float64)
    margin = int(0.04 * width)
    rect = (margin, margin, width - 2 * margin, height - 2 * margin)
    cv2.grabCut(image, mask, rect, background, foreground, 6, cv2.GC_INIT_WITH_RECT)
    product = np.where((mask == cv2.GC_FGD) | (mask == cv2.GC_PR_FGD), 255, 0)
    product = product.astype(np.uint8)
    sure = cv2.erode(product, np.ones((41, 41), np.uint8))
    maybe = cv2.dilate(product, np.ones((25, 25), np.uint8))
    refine = np.full((height, width), cv2.GC_BGD, np.uint8)
    refine[maybe > 0] = cv2.GC_PR_BGD
    refine[product > 0] = cv2.GC_PR_FGD
    refine[sure > 0] = cv2.GC_FGD
    cv2.grabCut(image, refine, None, background, foreground, 5, cv2.GC_INIT_WITH_MASK)
    product = np.where((refine == cv2.GC_FGD) | (refine == cv2.GC_PR_FGD), 255, 0)
    return fill_holes(largest_components(product.astype(np.uint8)), 0.02)


MODELS = {"sneakers": "u2net", "tote": "isnet-general-use", "headphones": "u2net", "lamp": "u2net"}
"""rembg model per photo: ISNet keeps the tote's handle loops open, U²-Net
keeps the sneakers whole (ISNet punches holes in the lace area)."""
_SESSIONS: dict[str, object] = {}


def matte(image: Image, name: str) -> Image:
    """Binary product mask: a rembg model through rembg, else GrabCut."""

    try:
        from PIL import Image as PILImage
        from rembg import new_session, remove
    except ImportError:
        print(f"{name}: rembg not installed, falling back to GrabCut")
        return grabcut(image)
    model = MODELS[name]
    if model not in _SESSIONS:
        _SESSIONS[model] = new_session(model)
    rgb = PILImage.fromarray(cv2.cvtColor(image, cv2.COLOR_BGR2RGB))
    alpha = np.array(remove(rgb, session=_SESSIONS[model], only_mask=True))
    # Threshold rather than trust the soft alpha: enclosed background (a
    # handle loop) comes back half-opaque and would be tinted.
    return ((alpha > 127) * 255).astype(np.uint8)


def feather(mask: Image, blur: float = 1.0) -> Image:
    return (cv2.GaussianBlur(mask, (0, 0), blur).astype(np.float32) / 255.0)[..., None]


def _sole_chroma(image: Image) -> Image:
    lab = cv2.cvtColor(image.astype(np.float32) / 255.0, cv2.COLOR_BGR2Lab)
    chroma = np.sqrt(lab[..., 1] ** 2 + lab[..., 2] ** 2)
    warm = (lab[..., 1] > 0) & (lab[..., 2] > 0)
    return np.clip((chroma - 21) / 11, 0, 1) * warm


def sole_band(image: Image) -> Image:
    """The gum soles as a binary band, sidewall shadow included."""

    # The sidewall in shadow loses chroma but is still sole: close the band
    # vertically (never far enough to bridge the front shoe's heel between the
    # two soles) and keep only the sole-sized components.
    band = ((_sole_chroma(image) > 0.5) * 255).astype(np.uint8)
    band = cv2.morphologyEx(band, cv2.MORPH_CLOSE, np.ones((25, 1), np.uint8))
    band = cv2.morphologyEx(band, cv2.MORPH_CLOSE, np.ones((9, 9), np.uint8))
    return cv2.dilate(largest_components(band, min_ratio=0.004), np.ones((3, 3), np.uint8))


def sole_weight(image: Image) -> Image:
    """How much a pixel is gum sole: the shoe's only warm, high-chroma part."""

    weight = np.maximum(_sole_chroma(image), sole_band(image).astype(np.float32) / 255.0)
    return cv2.GaussianBlur(weight.astype(np.float32), (0, 0), 1.2)[..., None]


def dark_mask(image: Image, mask: Image) -> Image:
    dark = ((hsv(image)[..., 2] < 0.72) * 255).astype(np.uint8)
    dark = cv2.morphologyEx(dark, cv2.MORPH_CLOSE, np.ones((9, 9), np.uint8))
    return fill_holes(cv2.bitwise_and(dark, mask))


def saturated_mask(image: Image, mask: Image) -> Image:
    vivid = ((hsv(image)[..., 1] > 0.33) * 255).astype(np.uint8)
    vivid = cv2.morphologyEx(vivid, cv2.MORPH_CLOSE, np.ones((9, 9), np.uint8))
    return fill_holes(cv2.bitwise_and(vivid, mask))


def blend(image: Image, recoloured: Image, weight: Image) -> Image:
    mixed = image.astype(np.float32) * (1 - weight) + recoloured.astype(np.float32) * weight
    return np.clip(mixed, 0, 255).astype(np.uint8)


def darken(image: Image) -> Image:
    colour = hls(image)
    colour[..., 1] = colour[..., 1] * 0.3 + 0.02
    colour[..., 2] *= 0.25
    return bgr(colour)


def colourise(image: Image, hue: float, saturation: float, light: float = 1.0) -> Image:
    colour = hls(image)
    colour[..., 0] = hue
    colour[..., 2] = saturation * (1 - np.abs(2 * colour[..., 1] - 1)) ** 0.5
    colour[..., 1] = np.clip(colour[..., 1] * light, 0, 1)
    return bgr(colour)


def whiten(image: Image, chroma_keep: float = 0.12, lift: float = 0.45) -> Image:
    """Pull toward white in Lab: chroma nearly gone, lightness lifted, shading kept."""

    lab = cv2.cvtColor(image.astype(np.float32) / 255.0, cv2.COLOR_BGR2Lab)
    out = lab.copy()
    out[..., 1] = lab[..., 1] * chroma_keep
    out[..., 2] = lab[..., 2] * chroma_keep
    out[..., 0] = np.clip(100 - (100 - lab[..., 0]) * (1 - lift), 0, 100)
    return np.clip(cv2.cvtColor(out, cv2.COLOR_Lab2BGR) * 255.0, 0, 255).astype(np.uint8)


def lighten(image: Image, keep: float = 0.62) -> Image:
    colour = hls(image)
    colour[..., 1] = 1 - (1 - colour[..., 1]) * keep
    colour[..., 2] *= 0.6
    return bgr(colour)


Recolour = Callable[[Image, Image], Image]
"""``(image, mask) -> image`` where ``mask`` is the binary product matte."""
VARIANTS: dict[str, tuple[str, Recolour]] = {
    "sneakers-black": (
        "sneakers",
        lambda i, m: blend(i, darken(i), feather(m) * (1 - sole_weight(i))),
    ),
    "sneakers-white": (
        "sneakers",
        lambda i, m: blend(i, whiten(i), feather(m) * (1 - sole_weight(i))),
    ),
    "tote-navy": ("tote", lambda i, m: blend(i, colourise(i, 222, 0.5, 0.5), feather(m))),
    "tote-black": ("tote", lambda i, m: blend(i, darken(i), feather(m))),
    "headphones-silver": (
        "headphones",
        lambda i, m: blend(i, lighten(i), feather(dark_mask(i, m))),
    ),
    "headphones-blue": (
        "headphones",
        lambda i, m: blend(i, colourise(i, 216, 0.5), feather(dark_mask(i, m))),
    ),
    "lamp-sage": (
        "lamp",
        lambda i, m: blend(i, colourise(i, 105, 0.26), feather(saturated_mask(i, m))),
    ),
    "lamp-cream": (
        "lamp",
        lambda i, m: blend(i, colourise(i, 38, 0.2, 1.28), feather(saturated_mask(i, m))),
    ),
}


def main() -> int:
    images = {name: load(name) for name in ("sneakers", "tote", "headphones", "lamp")}
    masks = {name: matte(image, name) for name, image in images.items()}
    for name, (base, recolour) in VARIANTS.items():
        target = HERE / f"{name}.jpg"
        cv2.imwrite(str(target), recolour(images[base], masks[base]), [cv2.IMWRITE_JPEG_QUALITY, 90])
        print(f"{target.name}: {target.stat().st_size // 1024} KB")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
