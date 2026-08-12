"""Generate the ThreatLens extension icons (dark lens/aperture motif).

Usage:  python generate_icons.py   (writes icon16.png / icon48.png / icon128.png)
Requires: Pillow
"""
from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw

OUT_DIR = Path(__file__).resolve().parent

SIZES = [16, 48, 128]
SS = 4  # supersampling factor for smooth edges


def _draw_icon(size: int) -> Image.Image:
    s = size * SS
    img = Image.new("RGBA", (s, s), (0, 0, 0, 0))
    d = ImageDraw.Draw(img)

    # Rounded-square background (deep navy, matching the dashboard)
    radius = int(s * 0.22)
    d.rounded_rectangle([0, 0, s - 1, s - 1], radius=radius, fill=(7, 11, 20, 255))

    cx = cy = s / 2

    # Outer lens ring (cyan)
    r_outer = s * 0.36
    d.ellipse(
        [cx - r_outer, cy - r_outer, cx + r_outer, cy + r_outer],
        outline=(34, 211, 238, 255),
        width=max(2, s // 14),
    )

    # Inner lens: radial gradient ring by stroke (cyan -> mint toward center)
    r_inner = int(s * 0.27)
    for i in range(r_inner, 0, -1):
        t = i / r_inner
        col = (
            int(8 + (52 - 8) * t),
            int(145 + (211 - 145) * t),
            int(178 + (153 - 178) * t),
            255,
        )
        d.ellipse([cx - i, cy - i, cx + i, cy + i], outline=col, width=1)

    # Aperture dot (dark center)
    r_dot = s * 0.07
    d.ellipse([cx - r_dot, cy - r_dot, cx + r_dot, cy + r_dot], fill=(7, 11, 20, 255))

    return img.resize((size, size), Image.LANCZOS)


if __name__ == "__main__":
    for size in SIZES:
        _draw_icon(size).save(OUT_DIR / f"icon{size}.png")
        print(f"{OUT_DIR / f'icon{size}.png'} written")
