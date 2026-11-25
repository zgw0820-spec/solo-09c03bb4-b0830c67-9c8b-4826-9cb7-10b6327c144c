"""pcapdiff: dual-ended TCP capture evidence comparison."""

__version__ = "1.0.0"

LIMIT_2GIB = 2 * 1024 ** 3

CATEGORY_CAPTURED = "captured"
CATEGORY_ACKED = "acked_only"
CATEGORY_MISSING = "missing"

CATEGORY_LABELS = {
    CATEGORY_CAPTURED: "收端抓到数据包",
    CATEGORY_ACKED: "仅被收端累计 ACK 确认",
    CATEGORY_MISSING: "收端无证据",
}

# Re-exported for convenient discovery; importing the package stays side-effect
# free and does not pull in Flask.
from .window_check import (  # noqa: E402,F401
    KIND_FULL as WINDOW_KIND_FULL,
    KIND_ZERO as WINDOW_KIND_ZERO,
    analyze_window,
    analyze_window_exhaustion,
)
