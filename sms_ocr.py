"""Read text from SMS screenshots with the optional local Tesseract engine."""

import subprocess
from io import BytesIO

from PIL import Image, ImageOps


MAX_SCREENSHOT_BYTES = 5 * 1024 * 1024
MAX_SCREENSHOT_DIMENSION = 4096
MAX_SCREENSHOT_PIXELS = 12_000_000
OCR_TIMEOUT = 10


class SMSOCRError(ValueError):
    """A screenshot could not supply text for the SMS field."""


def _prepare_screenshot(image_bytes):
    if len(image_bytes) > MAX_SCREENSHOT_BYTES:
        raise SMSOCRError("The screenshot exceeds the 5 MiB limit.")

    dimension_error = "Screenshot limits are 4096 pixels per side and 12 megapixels total."
    try:
        with Image.open(BytesIO(image_bytes), formats=("PNG", "JPEG")) as image:
            width, height = image.size
            if max(width, height) > MAX_SCREENSHOT_DIMENSION or width * height > MAX_SCREENSHOT_PIXELS:
                raise SMSOCRError(dimension_error)
            if getattr(image, "n_frames", 1) != 1:
                raise SMSOCRError("Upload a single-frame PNG or JPEG.")

            ImageOps.exif_transpose(image, in_place=True)
            mode = "RGBA" if image.has_transparency_data else "L"
            with image.convert(mode) as normalized, BytesIO() as png:
                normalized.info.clear()
                normalized.save(png, format="PNG")
                return png.getvalue()
    except (Image.DecompressionBombError, Image.DecompressionBombWarning):
        raise SMSOCRError(dimension_error) from None
    except SMSOCRError:
        raise
    except (OSError, SyntaxError, ValueError):
        raise SMSOCRError("The screenshot could not be read as PNG or JPEG.") from None


def extract_sms_text(image_bytes):
    """Recognize English text without writing the screenshot or OCR output to disk."""
    screenshot = _prepare_screenshot(image_bytes)
    try:
        result = subprocess.run(
            ["tesseract", "stdin", "stdout", "-l", "eng", "--psm", "11"],
            input=screenshot,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            check=True,
            timeout=OCR_TIMEOUT,
            creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
        )
    except subprocess.TimeoutExpired:
        raise SMSOCRError("Reading the screenshot took too long.") from None
    except (OSError, subprocess.CalledProcessError):
        raise SMSOCRError("Local OCR is unavailable.") from None

    text = result.stdout.decode("utf-8", errors="replace").strip()
    if not text:
        raise SMSOCRError("No text was found in the screenshot.")
    return text
