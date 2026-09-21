"""Runtime inference layer: loads a trained flow classifier once and wraps prediction.

Training code lives in the repository-root ``ml/`` directory and is never imported here.
This package is import-safe without scikit-learn installed: the model simply reports itself
as unavailable, and the pipeline falls back to the always-on statistical detectors.
"""
