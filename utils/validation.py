"""Input validation shared by the UI, the API and the scanners."""
from config import MAX_CSV_BYTES, MAX_TEXT_CHARS, MAX_UPLOAD_BYTES

PNG_SIG = b"\x89PNG\r\n\x1a\n"
JPEG_SIG = b"\xff\xd8\xff"
ALLOWED_EXT = {".png", ".jpg", ".jpeg"}
ALLOWED_MIME = {"image/png", "image/jpeg", "image/jpg"}


def validate_text(text, field="Message", max_chars=MAX_TEXT_CHARS):
    """Return (clean_text, error). error is None when the text is acceptable."""
    if text is None or not isinstance(text, str) or not text.strip():
        return "", f"{field} is empty. Please paste some text to analyse."
    if len(text) > max_chars:
        return "", f"{field} is too long (limit {max_chars:,} characters)."
    return text.replace("\x00", ""), None


def validate_image_upload(filename, content_type, data):
    """Check extension, declared MIME type, file signature and size. Return error text or None."""
    if not data:
        return "The uploaded file is empty."
    if len(data) > MAX_UPLOAD_BYTES:
        return f"The file is larger than {MAX_UPLOAD_BYTES // (1024 * 1024)} MB."
    name = (filename or "").lower()
    if not any(name.endswith(e) for e in ALLOWED_EXT):
        return "Unsupported file type. Please upload a PNG, JPG or JPEG image."
    if content_type and content_type.lower() not in ALLOWED_MIME:
        return "The file's declared type is not PNG or JPEG."
    is_png = data.startswith(PNG_SIG)
    is_jpg = data.startswith(JPEG_SIG)
    if not (is_png or is_jpg):
        return "The file contents do not look like a real PNG or JPEG image."
    if name.endswith(".png") and not is_png:
        return "The file extension (.png) does not match the file contents."
    if name.endswith((".jpg", ".jpeg")) and not is_jpg:
        return "The file extension (.jpg/.jpeg) does not match the file contents."
    return None


def validate_csv_upload(filename, data):
    if not data:
        return "The uploaded CSV is empty."
    if len(data) > MAX_CSV_BYTES:
        return f"The CSV is larger than {MAX_CSV_BYTES // (1024 * 1024)} MB."
    if not (filename or "").lower().endswith(".csv"):
        return "Please upload a .csv file."
    return None
