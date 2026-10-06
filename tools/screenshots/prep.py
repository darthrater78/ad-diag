"""Font and image helpers for run.sh (needs fonttools and pillow).

fonts <src> <dst>: writes Wine-friendly copies of the fonts the app asks for.
  - Cascadia Code: Wine's GDI+ looks a family up by the Regular face's full name, so
    "Cascadia Code Regular" never matches and WinForms falls back to Tahoma. The full
    name is set to the family name.
  - Selawik stands in for Segoe UI (not redistributable). It lacks the status-mark and
    box-drawing glyphs the app prints, and Wine's rich edit control doesn't fall back
    to another font, so they are merged in from DejaVu Sans.
crop <png>...: trims trailing rows that are all background colour.
"""
import sys
from pathlib import Path

EXTRA = [0x25CF, 0x2550, 0x2500, 0x2502, 0x250C, 0x2514, 0x25B2, 0x2715]  # ● ═ ─ │ ┌ └ ▲ ✕
DROP = ("GSUB", "GPOS", "GDEF", "DSIG", "kern", "hdmx", "VDMX", "LTSH", "MATH", "FFTM", "BASE", "JSTF", "meta")


def fonts(src: Path, dst: Path, dejavu: Path) -> None:
    from fontTools import subset
    from fontTools.merge import Merger
    from fontTools.ttLib import TTFont

    dst.mkdir(parents=True, exist_ok=True)
    for weight in ("Regular", "Bold"):
        f = TTFont(src / "cascadia" / "ttf" / "static" / f"CascadiaCode-{weight}.ttf")
        if weight == "Regular":
            for rec in f["name"].names:
                if rec.nameID == 4:
                    rec.string = "Cascadia Code"
        f.save(dst / f"CascadiaCode-{weight}.ttf")

    for sel, dv in (("selawk", "DejaVuSans"), ("selawkb", "DejaVuSans-Bold")):
        base = TTFont(src / "selawik" / f"{sel}.ttf")
        extra = TTFont(dejavu / f"{dv}.ttf")
        opts = subset.Options()
        opts.layout_features = []
        opts.name_IDs = ["*"]
        sub = subset.Subsetter(opts)
        sub.populate(unicodes=EXTRA)
        sub.subset(extra)
        for font in (base, extra):
            for tag in DROP:
                if tag in font:
                    del font[tag]
        a, b = dst / f"_{sel}_a.ttf", dst / f"_{sel}_b.ttf"
        base.save(a)
        extra.save(b)
        merged = Merger().merge([str(a), str(b)])
        merged["name"] = TTFont(src / "selawik" / f"{sel}.ttf")["name"]
        merged.save(dst / f"{sel}.ttf")
        a.unlink()
        b.unlink()


def crop(paths: list[str]) -> None:
    from PIL import Image

    for p in paths:
        im = Image.open(p).convert("RGB")
        bg = im.getpixel((im.width // 2, im.height - 2))
        last = im.height - 1
        while last > 0 and all(im.getpixel((x, last)) == bg for x in range(0, im.width - 24, 2)):
            last -= 1
        if last < im.height - 30:
            im = im.crop((0, 0, im.width, last + 24))
        im.save(p, optimize=True)


if __name__ == "__main__":
    if sys.argv[1] == "fonts":
        fonts(Path(sys.argv[2]), Path(sys.argv[3]), Path(sys.argv[4]))
    elif sys.argv[1] == "crop":
        crop(sys.argv[2:])
    else:
        sys.exit(f"unknown command {sys.argv[1]}")
