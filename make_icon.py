#!/usr/bin/env python3
"""Generate icon.ico / icon.png for the app: a blue shield with a check
(a security finding, corrected/verified) — matches the web favicon."""
from PIL import Image, ImageDraw

S = 1024
BLUE = (97, 175, 239, 255)   # #61afef
INK = (27, 31, 39, 255)      # #1b1f27
k = S / 256.0


def x(v):
    return v * k


img = Image.new("RGBA", (S, S), (0, 0, 0, 0))
d = ImageDraw.Draw(img)

# Shield: rounded-rect top + tapered lower sides down to a soft point.
d.rounded_rectangle([x(46), x(34), x(210), x(120)], radius=x(30), fill=BLUE)
d.polygon([(x(46), x(104)), (x(210), x(104)), (x(196), x(150)),
           (x(158), x(198)), (x(128), x(224)), (x(98), x(198)),
           (x(60), x(150))], fill=BLUE)

# Checkmark, dark ink, thick with rounded joints/ends.
lw = int(x(26))
p1, p2, p3 = (x(90), x(132)), (x(117), x(160)), (x(174), x(96))
d.line([p1, p2, p3], fill=INK, width=lw, joint="curve")
r = lw // 2
for p in (p1, p2, p3):
    d.ellipse([p[0] - r, p[1] - r, p[0] + r, p[1] + r], fill=INK)

img = img.resize((256, 256), Image.LANCZOS)
img.save("icon.ico", sizes=[(16, 16), (32, 32), (48, 48), (64, 64), (128, 128), (256, 256)])
img.save("icon.png")
print("wrote icon.ico + icon.png")
