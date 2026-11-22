from io import BytesIO
from pathlib import Path

import pytest
from PIL import Image

from qr_scanner import MAX_IMAGE_BYTES, MAX_IMAGE_DIMENSION, QRScanError, decode_qr_image


FIXTURES = Path(__file__).with_name("tests") / "fixtures" / "qr"


@pytest.mark.parametrize(
    ("filename", "expected"),
    [
        ("url.png", ("URL", "https://example.com")),
        ("text.jpg", ("SMS", "Meeting details: https://example.com/Agenda")),
    ],
)
def test_decodes_url_png_and_text_jpeg(filename, expected):
    assert decode_qr_image((FIXTURES / filename).read_bytes()) == expected


@pytest.mark.parametrize(
    ("filename", "explanation"),
    [
        ("unreadable.png", r"(?i)read|open"),
        ("no_code.png", r"(?i)no .*qr code"),
        ("multiple.png", r"(?i)multiple|more than one"),
        ("unsupported.png", r"(?i)wi-fi|unsupported"),
        ("payment.png", r"(?i)payment|unsupported"),
    ],
)
def test_rejects_unreadable_ambiguous_and_unsupported_images(filename, explanation):
    with pytest.raises(QRScanError, match=explanation) as error:
        decode_qr_image((FIXTURES / filename).read_bytes())

    assert "fixture-only" not in str(error.value)
    assert "fixture@example" not in str(error.value)


def make_image(size, image_format="PNG"):
    with Image.new("L", size) as image, BytesIO() as output:
        image.save(output, format=image_format)
        return output.getvalue()


def test_rejects_file_over_byte_limit_before_decoding():
    with pytest.raises(QRScanError, match=r"(?i)size|MiB"):
        decode_qr_image(bytes(MAX_IMAGE_BYTES + 1))


@pytest.mark.parametrize("size", [(MAX_IMAGE_DIMENSION + 1, 1), (4000, 3100)])
def test_rejects_oversized_image_dimensions_and_pixel_count(size):
    with pytest.raises(QRScanError, match=r"(?i)dimensions|pixels"):
        decode_qr_image(make_image(size))


def test_rejects_unsupported_image_format():
    with pytest.raises(QRScanError, match=r"(?i)PNG.*JPEG"):
        decode_qr_image(make_image((64, 64), "GIF"))
