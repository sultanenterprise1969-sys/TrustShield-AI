import io

from PIL import Image, ImageDraw, ImageFont


def make_png(text="", size=(900, 260)):
    img = Image.new("RGB", size, "white")
    if text:
        try:
            font = ImageFont.load_default(size=30)
        except TypeError:  # older Pillow
            font = ImageFont.load_default()
        ImageDraw.Draw(img).multiline_text((20, 20), text, fill="black", font=font)
    buf = io.BytesIO()
    img.save(buf, "PNG")
    return buf.getvalue()
