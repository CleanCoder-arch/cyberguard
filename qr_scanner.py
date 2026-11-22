from io import BytesIO
from unicodedata import category

from PIL import Image

from sms_url_extractor import extract_urls
from url_normalizer import SCHEME_PREFIX, URLValidationError, normalize_url


MAX_IMAGE_BYTES = 5 * 1024 * 1024
MAX_IMAGE_DIMENSION = 4096
MAX_IMAGE_PIXELS = 12_000_000
_PAYMENT_SCHEMES = {"bitcoin", "ethereum", "lightning", "payto", "upi"}
_STRUCTURED_SCHEMES = {
    "begin", "bizcard", "data", "file", "geo", "javascript", "mailto",
    "mecard", "mms", "mmsto", "otpauth", "sms", "smsto", "tel",
}
_UNSUPPORTED_PAYLOAD = "Unsupported QR payload. Scan an HTTP or HTTPS URL or plain text."


class QRScanError(ValueError):
    """A QR upload or payload cannot be scanned."""


def _classify_payload(payload):
    candidate = payload.strip()
    if not candidate:
        raise QRScanError("The QR code contains no text.")

    if len(candidate) >= 2 and candidate[0] in "\"'" and candidate[-1] == candidate[0]:
        candidate = candidate[1:-1]

    scheme_match = SCHEME_PREFIX.match(candidate)
    scheme = scheme_match[1].lower() if scheme_match else None
    remainder = candidate[scheme_match.end():] if scheme_match else ""
    has_whitespace = any(char.isspace() for char in candidate)
    bare_url = (
        (scheme is None or "." in scheme or scheme == "localhost")
        and not remainder.startswith("//")
        and not has_whitespace
        and (extract_urls(candidate) == [candidate] or scheme == "localhost")
    )
    if scheme in {"http", "https"} or candidate.startswith("//") or bare_url:
        try:
            normalize_url(payload)
        except URLValidationError:
            raise QRScanError("The QR code contains an invalid web URL.") from None
        return "URL", payload

    if scheme == "wifi":
        raise QRScanError("Wi-Fi credentials are unsupported in QR Image scans.")
    if scheme in _PAYMENT_SCHEMES:
        raise QRScanError("Payment links are unsupported in QR Image scans.")
    # Keep ordinary message labels distinct from URI schemes and structured QR data.
    if scheme in _STRUCTURED_SCHEMES or remainder.startswith("//") or (remainder and not has_whitespace):
        raise QRScanError(_UNSUPPORTED_PAYLOAD)
    return "SMS", payload


def _grayscale(image):
    if not image.has_transparency_data:
        return image.convert("L")

    grayscale = Image.new("L", image.size, 255)
    with image.convert("RGBA") as rgba, rgba.getchannel("A") as opacity:
        grayscale.paste(rgba, (0, 0), opacity)
    return grayscale


def decode_qr_image(image_bytes):
    """Decode a single QR symbol locally and return its scanner type and text."""
    if not image_bytes:
        raise QRScanError("The uploaded image is empty.")
    if len(image_bytes) > MAX_IMAGE_BYTES:
        raise QRScanError("The uploaded image exceeds the 5 MiB limit.")

    dimension_error = "Image limits are 4096 pixels per side and 12 megapixels total."
    try:
        with Image.open(BytesIO(image_bytes), formats=("PNG", "JPEG")) as image:
            width, height = image.size
            if max(width, height) > MAX_IMAGE_DIMENSION or width * height > MAX_IMAGE_PIXELS:
                raise QRScanError(dimension_error)
            if getattr(image, "n_frames", 1) != 1:
                raise QRScanError("Upload a single-frame PNG or JPEG image.")

            try:
                import zxingcpp
            except ImportError:
                raise QRScanError("The QR decoder is unavailable.") from None

            with _grayscale(image) as grayscale:
                codes = zxingcpp.read_barcodes(
                    grayscale,
                    formats=zxingcpp.BarcodeFormat.QRCode,
                    text_mode=zxingcpp.TextMode.Plain,
                    return_errors=True,
                )
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise QRScanError(dimension_error) from None
    except QRScanError:
        raise
    except (OSError, SyntaxError, ValueError, RuntimeError):
        raise QRScanError("The image could not be read as PNG or JPEG.") from None

    if len(codes) > 1:
        raise QRScanError("The image contains multiple QR codes. Upload an image with one code.")
    if not codes:
        raise QRScanError("No QR code could be read. Upload a clear image with one QR code.")
    code = codes[0]
    if not code.valid:
        raise QRScanError("The detected QR code could not be read. Upload a clearer image.")
    if code.content_type != zxingcpp.ContentType.Text:
        raise QRScanError(_UNSUPPORTED_PAYLOAD)
    payload = code.text
    if any(category(char) == "Cc" and char not in "\r\n\t" for char in payload):
        raise QRScanError(_UNSUPPORTED_PAYLOAD)
    return _classify_payload(payload)
