import os
import sys

_build = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "build")
if _build not in sys.path:
    sys.path.insert(0, _build)

from _netforge import *  # noqa: F401,E402