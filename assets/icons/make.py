"""Regenerate every RedX icon from the SVG sources (the crossed-scythe X).
  mark.svg / redx.svg   transparent mark (works on dark and light backgrounds)
  tile.svg              app-icon tile (dark rounded square + glow + mark)
  tile-small.svg        same, mark enlarged for <=48 px sizes
  tile-maskable.svg     full-bleed square, mark inside the 80% safe zone (PWA/Android maskable)
Needs: node + playwright-core (env PLAYWRIGHT_CORE=/path/to/node_modules/playwright-core if not global) +
Chrome (env CHROME=/path/to/chrome) for render.js, and Pillow.   usage: python3 make.py
"""
import os, subprocess
from PIL import Image
HERE = os.path.dirname(os.path.abspath(__file__)); os.chdir(HERE)
def render(svg, out, size, bg=None):
    subprocess.check_call(["node", "render.js", svg, out, str(size)] + ([bg] if bg else []))
os.makedirs("png", exist_ok=True)
render("tile.svg", "redx-icon-master-2048.png", 2048)
render("tile-small.svg", "/tmp/rx-small-1024.png", 1024)
render("tile-maskable.svg", "/tmp/rx-mask-1024.png", 1024)
render("mark.svg", "redx-mark-1024.png", 1024)
M = Image.open("redx-icon-master-2048.png").convert("RGBA")
S = Image.open("/tmp/rx-small-1024.png").convert("RGBA")
K = Image.open("/tmp/rx-mask-1024.png").convert("RGBA")
for s in (16, 32, 48, 64, 72, 96, 128, 144, 152, 167, 180, 192, 256, 384, 512, 1024):
    (S if s <= 48 else M).resize((s, s), Image.LANCZOS).save(f"png/redx-{s}.png")
K.resize((512, 512), Image.LANCZOS).save("png/redx-maskable-512.png")
K.resize((192, 192), Image.LANCZOS).save("png/redx-maskable-192.png")
# .ico: small sizes from the enlarged-mark tile
frames = [(S if s <= 48 else M).resize((s, s), Image.LANCZOS) for s in (16, 24, 32, 48, 64, 128, 256)]
frames[-1].save("redx.ico", format="ICO", sizes=[(f.width, f.height) for f in frames], append_images=frames[:-1])
M.resize((1024, 1024), Image.LANCZOS).save("redx.icns")
bgc = Image.new("RGB", (1024, 1024), (13, 7, 9)); t = M.resize((1024, 1024), Image.LANCZOS)
# iOS App Store icon must be a full-bleed square without alpha: use the maskable art
bgc.paste(K, (0, 0), K); bgc.save("png/ios-appstore-1024.png")
print(sorted(os.listdir(".")))
