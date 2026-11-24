"""Where generated artifacts live: $EDF6RE_OUT if set (generate.py --out sets it), else <repo>/out."""

import os
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
ENV = 'EDF6RE_OUT'


def out_root():
    value = os.environ.get(ENV)
    return Path(value).resolve() if value else ROOT / 'out'
