"""Cross-process packet plumbing: the priority queue and shared stat counters.

Both are created in the main process before the sniffer fork so the child shares
the same objects. Self-contained (multiprocessing + capture_core only); they
hold no app-level globals, so the definitions live here while the instances are
created in app.py's __main__.
"""
import time
import logging
import itertools
from multiprocessing import Queue, Value
from queue import Empty, Full

from capture_core import is_private_ip

logger = logging.getLogger(__name__)


# Minimum seconds between "queue full, packets dropped" warnings. Logging EVERY
# dropped packet turns a traffic burst into a logging storm that itself slows the
# capture path and bloats the log file, so drops are counted and summarized at
# most this often instead.
_DROP_LOG_INTERVAL = 5.0


class PacketQueue:
    def __init__(self, maxsize=5000):
        # multiprocessing.Queue is FIFO, so putting (priority, item) into one
        # queue did not actually prioritize external traffic. Two queues keep the
        # capture path non-blocking while process_packets drains external packets
        # first and only uses internal traffic when the high-priority lane is idle.
        self.maxsize = maxsize
        self.high = Queue(maxsize=maxsize)
        self.low = Queue(maxsize=maxsize)
        # Dropped-packet accounting. multiprocessing.Value so drops from the
        # forked internal-scanner process and the in-process sniffer thread sum
        # into one figure; throttle the warning to _DROP_LOG_INTERVAL.
        self._dropped = Value('q', 0)
        self._last_drop_log = Value('d', 0.0)
        # Round-robin turn counter for fair lane scheduling (see get()). Every
        # dequeue advances it, so it is the single hottest operation on the queue.
        # It is deliberately a process-local itertools.count, NOT a shared
        # multiprocessing.Value: get() is only ever called by the hub's in-process
        # worker threads (the forked internal scanner is a pure producer and only
        # calls put()), so the counter never needs to be shared across the fork.
        # next() on an itertools.count is a single C call under the GIL — atomic
        # and lock-free — which removes an OS-semaphore acquire from every single
        # dequeue and idle poll across all PACKET_WORKERS threads.
        self._turn = itertools.count(1)

    def _note_drop(self):
        with self._dropped.get_lock():
            self._dropped.value += 1
            total = self._dropped.value
        now = time.monotonic()
        with self._last_drop_log.get_lock():
            if now - self._last_drop_log.value >= _DROP_LOG_INTERVAL:
                self._last_drop_log.value = now
                should_log = True
            else:
                should_log = False
        if should_log:
            logger.warning(f"PacketQueue full: {total} packet(s) dropped so far "
                           "(raise PACKET_QUEUE_MAX / PACKET_WORKERS if sustained)")

    def dropped(self):
        with self._dropped.get_lock():
            return self._dropped.value

    def depth(self):
        """Current number of queued items across both lanes (capture backlog), or
        -1 where the platform doesn't implement qsize (e.g. macOS)."""
        try:
            return self.high.qsize() + self.low.qsize()
        except NotImplementedError:
            return -1

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
            self._note_drop()

    # Idle poll interval (seconds). Reached only when BOTH lanes are empty (see
    # get): bounds how soon a low-lane packet that lands during true idle is
    # noticed, after which that lane drains at full speed. It never delays a
    # high-priority packet — the blocking high.get wakes the instant one arrives
    # — so a coarse interval just trades idle latency for far fewer idle CPU
    # wakeups (~10/s here vs ~100/s at the old 10ms).
    _POLL_INTERVAL = 0.1

    # Fair-scheduling weight: out of every _LOW_EVERY dequeues, one services the
    # low (internal) lane FIRST. Strictly preferring the high lane starved the low
    # lane completely whenever the high lane stayed backlogged — e.g. a VPN flood
    # of external packets meant a LAN device's traffic (low lane) was never
    # processed at all. A 1-in-N slice guarantees internal traffic always drains
    # while still giving external packets the large majority of throughput.
    _LOW_EVERY = 4

    def _next_prefers_low(self):
        # next() on itertools.count is atomic under the GIL — no lock needed.
        return next(self._turn) % self._LOW_EVERY == 0

    def get(self, timeout=None):
        deadline = None if timeout is None else time.monotonic() + timeout
        while True:
            # Drain ready items WITHOUT blocking so a backlog on either lane is
            # serviced at full throughput. Order is high-lane-first MOST of the
            # time, but every _LOW_EVERY-th call probes the low lane first so a
            # permanently-backlogged high lane can no longer starve internal
            # traffic. (Blocking on the high lane first — as this once did — made
            # every low-lane packet pay the poll interval whenever the high lane
            # was idle, capping internal-traffic throughput at ~1/interval.)
            first, second = (self.low, self.high) if self._next_prefers_low() else (self.high, self.low)
            try:
                return first.get_nowait()
            except Empty:
                pass
            try:
                return second.get_nowait()
            except Empty:
                pass
            if timeout == 0:
                raise Empty
            # Both lanes empty: block on the high lane so an external packet wakes
            # us immediately; a low-lane arrival is picked up within one interval
            # by the get_nowait above on the next pass.
            high_wait = self._POLL_INTERVAL
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise Empty
                high_wait = min(high_wait, remaining)
            try:
                return self.high.get(timeout=high_wait)
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
    _FIELDS = ('tcp_packets', 'udp_packets', 'icmp_packets', 'total_bytes',
               'active_connections', 'fragmented_packets', 'processed_packets')

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
