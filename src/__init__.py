"""CVE Analytics package.

Importing any ``src.*`` submodule runs this module first, which pins
pyarrow's default memory pool to the system allocator.

Why: pyarrow bundles mimalloc as its default pool, and that build segfaults
on macOS arm64 (Python 3.14) when a *second* thread performs its first
allocation after another thread already has (``mi_thread_init`` recurses and
faults). The scan pipeline runs on background worker threads that convert
polars frames to Arrow via pyarrow, so the crash hit every multi-threaded
run. The system malloc pool is slightly slower but stable; data volumes here
are small enough that the difference is negligible.

The variable must be set before pyarrow's default pool is constructed, so it
lives here rather than in individual entry points.
"""

import os

os.environ.setdefault("ARROW_DEFAULT_MEMORY_POOL", "system")
