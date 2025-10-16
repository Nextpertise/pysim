#!/usr/bin/env python3.12
"""
Strict SIM PIN batcher (event-driven via pyscard CardMonitor).

CSV header (exactly 2 or 3 columns; case-insensitive):
    ICCID,PIN_NEW,PIN_OLD[o]

Rules:
 - ICCID: digits only, length 18..22
 - PIN_NEW: exactly 4 digits
 - PIN_OLD: optional; if present must be 4 digits. If absent or empty, fallback to --default-old-pin.
 - Error if header has >3 columns or missing required columns.

Behavior:
 - Listens for card insert/remove events (no blocking connect loop)
 - Reads EF.2FE2 ICCID (tries SELECT P2=0x0C then 0x00)
 - Per-card determine CHV1 status via VERIFY (0x9000 / 0x6984 / 0x63Cx)
 - If CHV OFF but PIN change needed -> ENABLE (old PIN) -> VERIFY -> CHANGE
 - After successful change, enforce desired pin-auth (--pin-auth on/off) only if needed.
 - Minimal console output; ALWAYS prints:
      * Already processed (ok) — ICCID in ORANJE
      * ICCID not in CSV — ICCID in ROOD
 - Logs to output_YYYYMMDD_<n>.csv
 - Ctrl-C stops gracefully
"""

from __future__ import annotations
import argparse
import csv
import os
import sys
import time
import signal
from datetime import datetime
from typing import Tuple, Dict, Set, Any

from smartcard.System import readers
from smartcard.Exceptions import CardConnectionException
from smartcard.CardMonitoring import CardMonitor, CardObserver

# colors (optional)
try:
    from colorama import init as _col_init, Fore, Style
    _col_init()
    GREEN, RED, YELLOW, RESET = Fore.GREEN, Fore.RED, Fore.YELLOW, Style.RESET_ALL
except Exception:
    GREEN = RED = YELLOW = RESET = ""

# APDUs
READ_BINARY_10 = [0x00, 0xB0, 0x00, 0x00, 0x0A]
SW_SUCCESS = (0x90, 0x00)


def logfile_name() -> str:
    today = datetime.now().strftime("%Y%m%d")
    n = 1
    while True:
        candidate = f"output_{today}_{n}.csv"
        if not os.path.exists(candidate):
            return candidate
        n += 1


def bcd_to_iccid(data_bytes: list[int]) -> str:
    digits = []
    for b in data_bytes:
        lo = b & 0x0F
        hi = (b >> 4) & 0x0F
        digits.append(str(lo))
        if hi != 0xF:
            digits.append(str(hi))
    return "".join(digits)


def pin_to_8bytes(pin: str) -> list[int]:
    b = [ord(c) for c in pin]
    b += [0xFF] * (8 - len(b))
    return b


def validate_iccid(iccid: str) -> Tuple[bool, str]:
    if not iccid.isdigit():
        return False, "ICCID must contain only digits"
    if not (18 <= len(iccid) <= 22):
        return False, "ICCID length must be 18..22"
    return True, ""


def validate_pin_4(pin: str) -> Tuple[bool, str]:
    if not pin.isdigit():
        return False, "PIN must contain only digits"
    if len(pin) != 4:
        return False, "PIN must be exactly 4 digits"
    return True, ""


def read_iccid(conn) -> str:
    # SELECT MF (try P2=0x0C then 0x00)
    last_sw = (0x6F, 0x00)
    for p2 in (0x0C, 0x00):
        _, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x00, p2, 0x02, 0x3F, 0x00])
        last_sw = (sw1, sw2)
        if (sw1, sw2) == SW_SUCCESS:
            break
    else:
        raise RuntimeError(f"SELECT MF failed: {hex(last_sw[0])} {hex(last_sw[1])}")

    last_sw = (0x6F, 0x00)
    for p2 in (0x0C, 0x00):
        _, sw1, sw2 = conn.transmit([0x00, 0xA4, 0x00, p2, 0x02, 0x2F, 0xE2])
        last_sw = (sw1, sw2)
        if (sw1, sw2) == SW_SUCCESS:
            break
    else:
        raise RuntimeError(f"SELECT EF.ICCID failed: {hex(last_sw[0])} {hex(last_sw[1])}")

    resp, sw1, sw2 = conn.transmit(READ_BINARY_10)
    if (sw1, sw2) != SW_SUCCESS:
        raise RuntimeError(f"READ BINARY failed: {hex(sw1)} {hex(sw2)}")
    return bcd_to_iccid(resp)


def verify_pin(conn, pin: str) -> tuple[int, int]:
    apdu = [0x00, 0x20, 0x00, 0x01, 0x08] + pin_to_8bytes(pin)
    _, sw1, sw2 = conn.transmit(apdu)
    return (sw1, sw2)


def enable_pin(conn, pin: str) -> tuple[int, int]:
    apdu = [0x00, 0x28, 0x00, 0x01, 0x08] + pin_to_8bytes(pin)
    _, sw1, sw2 = conn.transmit(apdu)
    return (sw1, sw2)


def disable_pin(conn, pin: str) -> tuple[int, int]:
    apdu = [0x00, 0x26, 0x00, 0x01, 0x08] + pin_to_8bytes(pin)
    _, sw1, sw2 = conn.transmit(apdu)
    return (sw1, sw2)


def change_pin(conn, old_pin: str, new_pin: str) -> tuple[int, int]:
    apdu = [0x00, 0x24, 0x00, 0x01, 0x10] + pin_to_8bytes(old_pin) + pin_to_8bytes(new_pin)
    _, sw1, sw2 = conn.transmit(apdu)
    return (sw1, sw2)


def load_strict_csv(path: str) -> dict:
    """
    - Header must be 2 or 3 columns.
    - Allowed header names (case-insensitive): ICCID, PIN_NEW, PIN_OLD or PIN_OLD[o]
    - Error if >3 columns, or missing ICCID/PIN_NEW.
    - Validate every row (ICCID digits 18..22, PIN_NEW 4 digits, PIN_OLD if present 4 digits).
    Returns mapping iccid -> {'new_pin':..., 'old_pin':...}
    """
    mapping = {}
    with open(path, newline="") as fh:
        rdr = csv.reader(fh)
        try:
            header = next(rdr)
        except StopIteration:
            raise ValueError("CSV is empty")
        hdr = [h.strip() for h in header]
        ncols = len(hdr)
        if ncols < 2:
            raise ValueError("CSV header must have at least ICCID and PIN_NEW")
        if ncols > 3:
            raise ValueError("CSV header has more than 3 columns (allowed: ICCID,PIN_NEW,PIN_OLD[o])")
        normalized = []
        for h in hdr:
            h0 = h.lower()
            if h0.endswith("[o]"):
                h0 = h0[:-3].strip()
            if h0.endswith("(o)"):
                h0 = h0[:-3].strip()
            normalized.append(h0)
        if "iccid" not in normalized or "pin_new" not in normalized:
            raise ValueError("CSV header must include ICCID and PIN_NEW (case-insensitive)")
        idx_iccid = normalized.index("iccid")
        idx_pin_new = normalized.index("pin_new")
        idx_pin_old = normalized.index("pin_old") if "pin_old" in normalized else None

        lineno = 1
        for row in rdr:
            lineno += 1
            if len(row) != ncols:
                raise ValueError(f"Row {lineno} has {len(row)} columns, expected {ncols}")
            iccid_raw = row[idx_iccid].strip()
            pin_new_raw = row[idx_pin_new].strip()
            pin_old_raw = ""
            if idx_pin_old is not None:
                pin_old_raw = row[idx_pin_old].strip()

            iccid_digits = "".join(ch for ch in iccid_raw if ch.isdigit())
            ok, msg = validate_iccid(iccid_digits)
            if not ok:
                raise ValueError(f"Row {lineno}: ICCID invalid: {msg}")
            ok, msg = validate_pin_4(pin_new_raw)
            if not ok:
                raise ValueError(f"Row {lineno}: PIN_NEW invalid: {msg}")
            if pin_old_raw:
                ok, msg = validate_pin_4(pin_old_raw)
                if not ok:
                    raise ValueError(f"Row {lineno}: PIN_OLD invalid: {msg}")
            mapping[iccid_digits] = {"new_pin": pin_new_raw, "old_pin": pin_old_raw}
    return mapping


class BatchObserver(CardObserver):
    """CardObserver die kaart-inserts verwerkt, gefilterd op een specifieke reader."""
    def __init__(self,
                 mapping: Dict[str, dict],
                 default_old_pin: str,
                 pin_auth_mode: str,
                 writer: csv.writer,
                 quiet: bool,
                 debug: bool,
                 processed_ok: Set[str],
                 remaining: Set[str],
                 selected_reader_name: str):
        super().__init__()
        self.mapping = mapping
        self.default_old_pin = default_old_pin
        self.pin_auth_mode = pin_auth_mode
        self.writer = writer
        self.quiet = quiet
        self.debug = debug
        self.processed_ok = processed_ok
        self.remaining = remaining
        self.selected_reader_name = selected_reader_name
        self.last_seen_iccid = None
        self.last_seen_ts = 0.0
        self.debounce_s = 0.4  # ignore duplicate inserts within this window

    def update(self, observable: Any, actions: Any = None):
        # pyscard passes a tuple (added_cards, removed_cards)
        try:
            added_cards, _removed_cards = actions
        except Exception:
            added_cards, _removed_cards = ([], [])

        now = time.time()
        for card in (added_cards or []):
            # open connection
            try:
                conn = card.createConnection()
                conn.connect()
            except Exception:
                continue

            # filter on selected reader
            try:
                rname = conn.getReader()
            except Exception:
                rname = ""
            if self.selected_reader_name and rname and (rname != self.selected_reader_name):
                # not our target reader; ignore
                try:
                    conn.disconnect()
                except Exception:
                    pass
                continue

            # read ICCID
            try:
                iccid = read_iccid(conn)
            except Exception as e:
                if not self.quiet:
                    print(RED + f"ICCID read error: {e}" + RESET, flush=True)
                try:
                    conn.disconnect()
                except Exception:
                    pass
                continue

            # debounce duplicate events for same card
            if self.last_seen_iccid == iccid and (now - self.last_seen_ts) < self.debounce_s:
                try:
                    conn.disconnect()
                except Exception:
                    pass
                continue
            self.last_seen_iccid, self.last_seen_ts = iccid, now

            # already processed? ALWAYS print (orange)
            if iccid in self.processed_ok:
                print(f"{YELLOW}Already processed (ok): {iccid}{RESET}", flush=True)
                try:
                    conn.disconnect()
                except Exception:
                    pass
                continue

            if not self.quiet:
                print(f"Card detected: {iccid}", flush=True)

            # not in CSV? ALWAYS print (red)
            if iccid not in self.mapping:
                msg = "ICCID not in CSV"
                print(RED + f"{msg}: {iccid}" + RESET, flush=True)
                self.writer.writerow([iccid, "fail", msg])
                try:
                    conn.disconnect()
                except Exception:
                    pass
                continue

            entry = self.mapping[iccid]
            new_pin = entry["new_pin"]
            old_pin = entry["old_pin"] or self.default_old_pin

            # 1) determine CHV1 status via VERIFY(old_pin)
            sw = verify_pin(conn, old_pin)
            if self.debug:
                print("VERIFY old_pin SW:", hex(sw[0]), hex(sw[1]), flush=True)
            if sw == SW_SUCCESS:
                chv_enabled_cur = True
                verified = True
            else:
                if sw[0] == 0x69 and sw[1] == 0x84:
                    chv_enabled_cur = False
                    verified = False
                elif sw[0] == 0x63:
                    chv_enabled_cur = True
                    verified = False
                else:
                    chv_enabled_cur = None
                    verified = False

            # 2) if CHV OFF but we need to change PIN -> enable, then verify (update status)
            if not verified and chv_enabled_cur is False:
                swe = enable_pin(conn, old_pin)
                if self.debug:
                    print("ENABLE old_pin SW:", hex(swe[0]), hex(swe[1]), flush=True)
                if swe == SW_SUCCESS:
                    chv_enabled_cur = True
                    sw = verify_pin(conn, old_pin)
                    if self.debug:
                        print("VERIFY after enable SW:", hex(sw[0]), hex(sw[1]), flush=True)
                    verified = (sw == SW_SUCCESS)
                else:
                    msg = "CHV enable/verify failed"
                    if not self.quiet:
                        print(RED + msg + RESET, flush=True)
                    self.writer.writerow([iccid, "fail", msg])
                    try:
                        conn.disconnect()
                    except Exception:
                        pass
                    continue

            # 3) change PIN if verified
            if verified:
                swc = change_pin(conn, old_pin, new_pin)
                if self.debug:
                    print("CHANGE CHV SW:", hex(swc[0]), hex(swc[1]), flush=True)
                if swc == SW_SUCCESS:
                    if not self.quiet:
                        print(GREEN + f"OK: PIN changed for {iccid}" + RESET, flush=True)
                    self.writer.writerow([iccid, "ok", "Pin changed successfully"])
                    self.processed_ok.add(iccid)
                    self.remaining.discard(iccid)

                    # 4) enforce desired pin-auth only if needed
                    desired = None
                    if self.pin_auth_mode in ("on", "1"):
                        desired = True
                    elif self.pin_auth_mode in ("off", "0"):
                        desired = False

                    if desired is not None:
                        # ensure we know current state; infer via VERIFY(new_pin) if needed
                        if chv_enabled_cur is None:
                            sw_check = verify_pin(conn, new_pin)
                            if self.debug:
                                print("VERIFY new_pin for status SW:", hex(sw_check[0]), hex(sw_check[1]), flush=True)
                            if sw_check == SW_SUCCESS:
                                chv_enabled_cur = True
                            elif sw_check[0] == 0x69 and sw_check[1] == 0x84:
                                chv_enabled_cur = False
                            elif sw_check[0] == 0x63:
                                chv_enabled_cur = True
                            else:
                                chv_enabled_cur = None

                        if chv_enabled_cur is not None and chv_enabled_cur != desired:
                            if desired:
                                swe2 = enable_pin(conn, new_pin)
                                if self.debug:
                                    print("ENABLE new_pin SW:", hex(swe2[0]), hex(swe2[1]), flush=True)
                                if swe2 != SW_SUCCESS and not self.quiet:
                                    print(YELLOW + "Warning: enable CHV after change failed" + RESET, flush=True)
                                else:
                                    chv_enabled_cur = True
                            else:
                                swd = disable_pin(conn, new_pin)
                                if self.debug:
                                    print("DISABLE new_pin SW:", hex(swd[0]), hex(swd[1]), flush=True)
                                if swd != SW_SUCCESS and not self.quiet:
                                    print(YELLOW + "Warning: disable CHV after change failed" + RESET, flush=True)
                                else:
                                    chv_enabled_cur = False
                else:
                    code = f"{hex(swc[0])}{hex(swc[1])[2:]}"
                    msg = f"CHANGE CHV failed {code}"
                    if not self.quiet:
                        print(RED + msg + RESET, flush=True)
                    self.writer.writerow([iccid, "fail", msg])
            else:
                # verify failed
                if sw[0] == 0x63:
                    retries = sw[1] & 0x0F
                    msg = f"PIN verify failed, {retries} retries left - set PIN_OLD in CSV or use --default-old-pin"
                else:
                    msg = "PIN verify failed"
                if not self.quiet:
                    print(RED + msg + RESET, flush=True)
                self.writer.writerow([iccid, "fail", msg])

            # done with this card
            try:
                conn.disconnect()
            except Exception:
                pass


def main() -> None:
    ap = argparse.ArgumentParser(description="Strict SIM PIN batcher (ICCID,PIN_NEW,PIN_OLD[o]) — event-driven")
    ap.add_argument("-?", action="help", help="show this help and exit")
    ap.add_argument("csv", nargs="?", help="Input CSV (ICCID,PIN_NEW,PIN_OLD[o])")
    ap.add_argument("--reader", type=int, default=0, help="PC/SC reader index (default 0)")
    ap.add_argument("--default-old-pin", default="0000", help="Fallback PIN_OLD if empty (default 0000)")
    ap.add_argument("--pin-auth", choices=["on", "off", "1", "0"], default="on",
                    help="Desired end state for PIN authentication (default: on)")
    ap.add_argument("--quiet", action="store_true", help="Reduce console output")
    ap.add_argument("--debug", action="store_true", help="Show APDU SW codes for debugging")

    if len(sys.argv) == 1:
        ap.print_help()
        sys.exit(0)
    args = ap.parse_args()
    if not args.csv:
        ap.error("missing CSV path")

    ok, msg = validate_pin_4(args.default_old_pin)
    if not ok:
        ap.error(f"--default-old-pin invalid: {msg}")

    # validate CSV
    try:
        mapping = load_strict_csv(args.csv)
    except Exception as e:
        print(RED + "CSV error: " + str(e) + RESET)
        sys.exit(1)

    # list readers & select
    rlist = readers()
    if not rlist:
        print(RED + "No PC/SC readers detected." + RESET)
        sys.exit(1)
    if args.reader < 0 or args.reader >= len(rlist):
        print(RED + f"Reader index {args.reader} out of range (found {len(rlist)})" + RESET)
        sys.exit(1)
    selected_reader_name = str(rlist[args.reader])
    if not args.quiet:
        print("Using reader:", selected_reader_name)

    # logging file
    logname = logfile_name()
    logf = open(logname, "w", newline="")
    writer = csv.writer(logf)
    writer.writerow(["iccid", "status", "message"])
    logf.flush()
    if not args.quiet:
        print(f"Logging to: {logname}")
        print("Ready. Insert SIM (Ctrl-C to exit).")

    processed_ok: Set[str] = set()
    remaining: Set[str] = set(mapping.keys())

    # Card monitor setup (monitors all readers; we filter inside observer)
    monitor = CardMonitor()
    observer = BatchObserver(mapping, args.default_old_pin, args.pin_auth, writer,
                             args.quiet, args.debug, processed_ok, remaining,
                             selected_reader_name)
    monitor.addObserver(observer)

    # Graceful shutdown on Ctrl-C
    stop = False

    def _sigint(_sig, _frm):
        nonlocal stop
        stop = True
        print("\nStopping...", flush=True)

    signal.signal(signal.SIGINT, _sigint)

    try:
        while not stop:
            # auto-exit when all processed ok
            if not remaining:
                if not args.quiet:
                    print("All CSV ICCIDs processed successfully. Exiting.", flush=True)
                break
            time.sleep(0.2)
    finally:
        try:
            monitor.deleteObserver(observer)
        except Exception:
            pass
        try:
            logf.flush()
            logf.close()
        except Exception:
            pass


if __name__ == "__main__":
    main()

