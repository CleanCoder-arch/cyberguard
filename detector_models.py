from functools import lru_cache
from pathlib import Path

import joblib


MODELS_DIR = Path(__file__).resolve().parent / "models"


class DetectorUnavailableError(RuntimeError):
    """Raised when a detector's model artifacts cannot be loaded."""


@lru_cache(maxsize=2)
def load_artifacts(detector, *paths):
    try:
        return tuple(joblib.load(path) for path in paths)
    except Exception as error:
        raise DetectorUnavailableError(
            f"The {detector} detector is unavailable because its model files could not be loaded."
        ) from error
