"""Screenshot scanner: validate -> Pillow -> OCR (Tesseract) -> message pipeline -> link scanner.

Images are processed in memory only and are never written to disk by this module.
This scanner reads TEXT. It cannot detect forged logos, edited receipts or deepfakes.
"""
import io

from PIL import Image, ImageOps, UnidentifiedImageError

import config
from scanners.message_scanner import scan_message
from services.risk_scoring import assess
from utils.validation import validate_image_upload

Image.MAX_IMAGE_PIXELS = config.MAX_IMAGE_PIXELS  # Pillow raises DecompressionBombError above 2x this


def run_ocr(img) -> dict:
    """Return {'status','text','confidence','message'}. Never raises."""
    try:
        import pytesseract
    except ImportError:
        return {"status": "unavailable", "text": "", "confidence": None,
                "message": "pytesseract is not installed. Run: pip install pytesseract"}
    try:
        d = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT, timeout=30)
    except pytesseract.TesseractNotFoundError:
        return {"status": "unavailable", "text": "", "confidence": None,
                "message": "Tesseract OCR is not installed on this server (e.g. sudo apt install tesseract-ocr)."}
    except Exception as e:
        return {"status": "failed", "text": "", "confidence": None, "message": f"OCR failed ({type(e).__name__})."}
    lines, confs = {}, []
    for i, w in enumerate(d.get("text", [])):
        w = (w or "").strip()
        if not w:
            continue
        lines.setdefault((d["block_num"][i], d["par_num"][i], d["line_num"][i]), []).append(w)
        try:
            c = float(d["conf"][i])
            if c >= 0:
                confs.append(c)
        except (ValueError, TypeError):
            pass
    text = "\n".join(" ".join(v) for _, v in sorted(lines.items()))
    return {"status": "ok" if text else "no_text", "text": text,
            "confidence": round(sum(confs) / len(confs), 1) if confs else None, "message": ""}


def scan_image(filename, content_type, data) -> dict:
    err = validate_image_upload(filename, content_type, data)
    if err:
        return {"ok": False, "scan_type": "image", "error": err}
    try:
        with Image.open(io.BytesIO(data)) as probe:
            probe.verify()
        img = Image.open(io.BytesIO(data))
        if img.format not in ("PNG", "JPEG"):
            return {"ok": False, "scan_type": "image", "error": "Only PNG and JPEG images are supported."}
        if img.width * img.height > config.MAX_IMAGE_PIXELS:
            return {"ok": False, "scan_type": "image", "error": "The image has too many pixels to process safely."}
        img = ImageOps.autocontrast(ImageOps.exif_transpose(img).convert("L"))
        if img.width < 1000:  # small screenshots OCR better when enlarged
            f = min(3, 1000 / max(1, img.width))
            img = img.resize((int(img.width * f), int(img.height * f)))
    except (UnidentifiedImageError, Image.DecompressionBombError, OSError, SyntaxError, ValueError):
        return {"ok": False, "scan_type": "image", "error": "The image is corrupted or could not be read."}

    ocr = run_ocr(img)
    ocr_limits = ["Only the TEXT in the image was analysed. Forged logos, edited receipts, deepfakes and "
                  "manipulated documents cannot be detected by this scanner.",
                  "The image was processed in memory and not stored."]
    if ocr["status"] != "ok" or len(ocr["text"]) < 10:
        msg = ocr["message"] or "No readable text was found (the image may be blurry, very small, or contain no text)."
        result = assess([], sufficient=False, insufficient_reason=msg, limitations=ocr_limits)
        result.update({"ok": True, "scan_type": "image", "ocr": ocr, "extracted_urls": [], "url_results": [],
                       "summary": f"No text analysed ({ocr['status']})"})
        return result

    result = scan_message(ocr["text"], scan_type="image")
    if not result["ok"]:
        return result
    result["ocr"] = ocr
    result["limitations"] = ocr_limits + [l for l in result["limitations"] if "pasted" not in l]
    if ocr["confidence"] is not None and ocr["confidence"] < 60:
        result["limitations"].insert(0, f"OCR confidence is low ({ocr['confidence']}%). Text may be misread; please review it.")
    result["summary"] = "OCR text: " + result["summary"]
    return result
