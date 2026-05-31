"""Cross-process packet plumbing: the priority queue and shared stat counters.

Both are created in the main process before the sniffer fork so the child shares
the same objects. Self-contained (multiprocessing + capture_core only); they
hold no app-level globals, so the definitions live here while the instances are
created in app.py's __main__.
"""
import time
import logging
from multiprocessing import Queue, Value
from queue import Empty, Full

from capture_core import is_private_ip

logger = logging.getLogger(__name__)


class PacketQueue:
    def __init__(self, maxsize=5000):
        # multiprocessing.Queue is FIFO, so putting (priority, item) into one
        # queue did not actually prioritize external traffic. Two queues keep the
        # capture path non-blocking while process_packets drains external packets
        # first and only uses internal traffic when the high-priority lane is idle.
        self.high = Queue(maxsize=maxsize)
        self.low = Queue(maxsize=maxsize)

    def _is_external(self, item):
        if 'ip_src' in item or 'ip_dst' in item:
            return not (is_private_ip(item.get('ip_src', '')) and is_private_ip(item.get('ip_dst', '')))
        if 'ip' in item:
            return not is_private_ip(item.get('ip', ''))
        return True

    def put(self, item):
        try:
            is_external = self._is_external(item)
            priority = 1 if is_external else 5
            target = self.high if is_external else self.low
            target.put_nowait((priority, item))
            logger.debug(f"Packet queued: {item.get('protocol')}, {'external' if is_external else 'internal'}")
        except Full:
            logger.warning("Queue full, packet dropped")

    def get(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            if timeout == 0:
                try:
                    return self.high.get_nowait()
                except Empty:
                    return self.low.get_nowait()
            high_wait = 0.01
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Empty
                high_wait = min(high_wait, remaining)
            try:
                return self.high.get(timeout=high_wait)
            except Empty:
                pass
            try:
                return self.low.get_nowait()
            except Empty:
                pass
            if deadline is not None and time.monotonic() >= deadline:
                raise Empty

    def empty(self):
        return self.high.empty() and self.low.empty()


class SharedStats:
    """Cross-process packet counters backed by multiprocessing.Value (shared
    memory) instead of a Manager().dict() proxy.

    A Manager proxy serializes every read/write over a socket to the manager
    process. Updating it on every captured packet from two processes becomes a
    hard IPC bottleneck at high packet rates and makes the sniffer drop frames at
    the kernel. Value uses a shared-memory cell with a tiny lock, which is orders
    of magnitude cheaper. Created before fork so children share the same cells."""
    _FIELDS = ('tcp_packets', 'udp_packets', 'icmp_packets', 'total_bytes', 'active_connections', 'fragmented_packets')

    def __init__(self):
        # 'q' = signed 64-bit, so total_bytes cannot overflow under sustained load.
        self._v = {name: Value('q', 0) for name in self._FIELDS}

    def incr(self, name, amount=1):
        v = self._v[name]
        with v.get_lock():
            v.value += amount

    def set(self, name, value):
        v = self._v[name]
        with v.get_lock():
            v.value = value

    def snapshot(self):
        return {name: v.value for name, v in self._v.items()}
