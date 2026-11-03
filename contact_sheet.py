"""
Combine rendered setup screens into contact sheets: up to 3 x 3 screens per image, each at
the VGA's own resolution (the 2x renderings halved: every pixel again one of the screen's),
with its number and title above it. Fewer attachments, and each still readable when opened.
"""

from __future__ import annotations

from pathlib import Path

from PIL import Image, ImageDraw, ImageFont

SIDE = 3  # screens per row and per column
GAP = 6  # pixels between the screens
CAPTION = 24  # height of the title bar above each screen
BACKGROUND = (48, 48, 48)
CAPTION_TEXT = (230, 230, 230)


def save_compact(image: Image.Image, out: Path, quality: int = 85) -> Path:
    """Save as PNG (out) when the picture has at most 256 colours (text-mode screens), else as
    JPEG (out with .jpg): the firmware's photo backgrounds of the graphical UEFI setups make
    a PNG of about 600 KB a page, too much for 60 pages and their sheets in one Discord
    message; as JPEG about 120 KB. Returns the file written."""
    if image.getcolors(256) is not None:
        image.save(out, optimize=True)
        return out
    jpg = out.with_suffix(".jpg")
    image.convert("RGB").save(jpg, quality=quality, optimize=True)
    return jpg


def sheet(screens: list[tuple[int, str, Path]], out: Path) -> Path:
    """Draw [(number, title, image file)] (at most SIDE x SIDE) into out."""
    tiles = []
    for number, title, path in screens[: SIDE * SIDE]:
        with Image.open(path) as image:
            tile = image.convert("RGB")
        if tile.width >= 1280:  # (a 2x text-mode rendering; drawn pictures stay as they are)
            tile = tile.resize((tile.width // 2, tile.height // 2), Image.Resampling.NEAREST)
        tiles.append((f"{number}: {title}", tile))
    width = max(tile.width for _, tile in tiles)
    height = max(tile.height for _, tile in tiles) + CAPTION
    cols = min(SIDE, len(tiles))
    rows = -(-len(tiles) // SIDE)
    canvas = Image.new(
        "RGB", (cols * width + (cols + 1) * GAP, rows * height + (rows + 1) * GAP), BACKGROUND
    )
    draw = ImageDraw.Draw(canvas)
    font = ImageFont.load_default(size=16)
    for k, (caption, tile) in enumerate(tiles):
        x = GAP + (k % SIDE) * (width + GAP)
        y = GAP + (k // SIDE) * (height + GAP)
        while caption and draw.textlength(caption, font=font) > width - 8:
            caption = caption[:-1]  # (a long title: cut to the screen's width)
        draw.text((x + 4, y + 3), caption, fill=CAPTION_TEXT, font=font)
        canvas.paste(tile, (x, y + CAPTION))
    return save_compact(canvas, out, quality=80)
