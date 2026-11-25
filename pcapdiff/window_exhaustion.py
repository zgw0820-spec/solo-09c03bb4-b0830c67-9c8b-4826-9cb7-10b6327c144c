"""Compatibility alias for :mod:`pcapdiff.window_check`.

The receive-window exhaustion feature is implemented in
:mod:`pcapdiff.window_check`; this module re-exports its public API under the
descriptive ``window_exhaustion`` name.
"""

from .window_check import *  # noqa: F401,F403
from .window_check import (  # noqa: F401
    END_CAPTURE_END,
    END_FIN,
    END_RECOVERED,
    END_RST,
    END_SWITCH,
    KIND_FULL,
    KIND_LABELS,
    KIND_ZERO,
    MAX_WSCALE_SHIFT,
    TERMINAL_REASONS,
    ListEpisodeSink,
    WindowEpisode,
    WindowReport,
    analyze_window,
    analyze_window_exhaustion,
    check_receive_window,
    payload_data_offset,
    window_exhaustion_check,
)
