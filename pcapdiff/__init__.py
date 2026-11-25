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
