#!/usr/bin/env python3
"""
capture_sources.py - Alternative packet *sources* for the hub.

Where ``capture_core`` knows how to turn a single scapy packet into fields, this
module knows how to *produce* scapy packets from things other than a live NIC.
Right now that means **tailing pcap files** (the output of the FritzDump module,
which streams a FRITZ!Box capture to ``modules/FritzDump/dumps/``), so a hub with
no usable capture interface can still be fed real traffic.

Design notes
------------
* Pure: depends only on scapy + stdlib. No Flask, no DB, no app globals — so it
  can be unit-tested and reused by a sensor exactly like ``capture_core``.
* Tail semantics: a pcap that FritzDump is still writing grows on disk. We parse
  the 24-byte classic-pcap global header once (endianness + link type), then walk
  16-byte record headers from a remembered byte offset, yielding only *complete*
  records and leaving a half-written trailing record for the next poll. This is
  robust to partial writes and to the file being rotated/truncated underneath us.
* Classic pcap only (magic ``a1b2c3d4`` / ``a1b23c4d``, either endianness). A
  pcapng file simply never matches and the reader stays inert (logged by caller).
"""

import os
import struct

# scapy is already a hard dependency of capture_core; import the link-layer
# decoders we map pcap LINKTYPE_* values onto.
from scapy.all import Ether, IP, CookedLinux

# Capture-file extensions we will tail under the dump directory.
PCAP_EXTENSIONS = {".pcap", ".pcapng", ".eth", ".cap", ".dmp"}

# classic-pcap framing
_GLOBAL_HDR_LEN = 24
_REC_HDR_LEN = 16
# Reject an incl_len larger than this as corruption rather than trying to buffer
# a multi-GB "record" (a desynced offset would otherwise read garbage lengths).
_MAX_SNAPLEN = 262_144

# pcap LINKTYPE -> scapy decoder. Default to Ethernet (what a FRITZ!Box emits).
_LINKTYPE_DECODERS = {
    1: Ether,        # LINKTYPE_ETHERNET
    101: IP,         # LINKTYPE_RAW (bare IP)
    113: CookedLinux,  # LINKTYPE_LINUX_SLL
}

# global-header magic -> (struct endian prefix). Nanosecond variants decode the
# same for our purposes (we ignore timestamps).
_MAGICS = {
    b"\xd4\xc3\xb2\xa1": "<",  # us, little-endian
    b"\xa1\xb2\xc3\xd4": ">",  # us, big-endian
    b"\x4d\x3c\xb2\xa1": "<",  # ns, little-endian
    b"\xa1\xb2\x3c\x4d": ">",  # ns, big-endian
}


class PcapTailReader:
    """Incrementally read complete packets from one growing classic-pcap file."""

    def __init__(self, path):
        self.path = path
        self.offset = 0          # next unread byte
        self.endian = None       # set once the global header is parsed
        self.rec_fmt = None
        self.decoder = Ether
        self._header_ok = False

    def _parse_global_header(self, hdr):
        endian = _MAGICS.get(hdr[:4])
        if endian is None:
            return False
        linktype = struct.unpack(endian + "I", hdr[20:24])[0]
        self.endian = endian
        self.rec_fmt = endian + "IIII"
        self.decoder = _LINKTYPE_DECODERS.get(linktype, Ether)
        self._header_ok = True
        return True

    def _decode(self, raw):
        try:
            return self.decoder(raw)
        except Exception:
            return None

    def read_new(self, byte_budget=8 * 1024 * 1024, max_packets=5000):
        """Return a list of newly-available scapy packets. Advances the internal
        offset only past records that were fully present on disk."""
        pkts = []
        try:
            with open(self.path, "rb") as f:
                f.seek(0, os.SEEK_END)
                size = f.tell()
                # Rotation/truncation: file shrank below where we were reading.
                if size < self.offset:
                    self.offset = 0
                    self._header_ok = False
                if not self._header_ok:
                    if size < _GLOBAL_HDR_LEN:
                        return pkts                       # header not written yet
                    f.seek(0)
                    if not self._parse_global_header(f.read(_GLOBAL_HDR_LEN)):
                        return pkts                       # not a classic pcap
                    self.offset = _GLOBAL_HDR_LEN
                if size <= self.offset:
                    return pkts
                f.seek(self.offset)
                data = f.read(min(byte_budget, size - self.offset))
        except (OSError, FileNotFoundError):
            return pkts

        pos = 0
        n = len(data)
        while n - pos >= _REC_HDR_LEN and len(pkts) < max_packets:
            _ts_sec, _ts_usec, incl_len, _orig_len = struct.unpack(
                self.rec_fmt, data[pos:pos + _REC_HDR_LEN])
            if incl_len > _MAX_SNAPLEN:
                # Desynced/corrupt; stop and let the next poll retry from here so
                # we never advance the offset into garbage.
                break
            if n - pos - _REC_HDR_LEN < incl_len:
                break                                     # record still being written
            raw = data[pos + _REC_HDR_LEN:pos + _REC_HDR_LEN + incl_len]
            pos += _REC_HDR_LEN + incl_len
            pkt = self._decode(raw)
            if pkt is not None:
                pkts.append(pkt)
        self.offset += pos
        return pkts


class FritzDumpSource:
    """Tail every capture file under a directory tree (recursively), so a
    FritzDump ``home`` run that fans out into per-interface pcaps in a fresh
    timestamped sub-directory is picked up automatically."""

    def __init__(self, dump_dir):
        self.dump_dir = dump_dir
        self.readers = {}        # path -> PcapTailReader

    def _discover(self):
        files = []
        try:
            for root, _dirs, names in os.walk(self.dump_dir):
                for name in names:
                    if os.path.splitext(name)[1].lower() in PCAP_EXTENSIONS:
                        files.append(os.path.join(root, name))
        except OSError:
            pass
        return files

    def poll(self, byte_budget=8 * 1024 * 1024, max_packets=5000):
        """Discover capture files and return all packets newly appended since the
        last poll across all of them."""
        out = []
        present = self._discover()
        for path in present:
            reader = self.readers.get(path)
            if reader is None:
                reader = PcapTailReader(path)
                self.readers[path] = reader
            try:
                out.extend(reader.read_new(byte_budget=byte_budget,
                                           max_packets=max_packets))
            except Exception:
                # A single unreadable file must never stop the others.
                continue
            if len(out) >= max_packets:
                break
        # Forget readers whose files vanished, so the dict can't grow unbounded
        # across FritzDump's rotate-and-delete cycles.
        present_set = set(present)
        for gone in [p for p in self.readers if p not in present_set]:
            del self.readers[gone]
        return out
