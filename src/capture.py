from __future__ import annotations

import time
from typing import Any, Dict, List

try:
    from scapy.all import ICMP, IP, TCP, UDP, sniff
except ImportError:  # pragma: no cover - handled gracefully during runtime
    ICMP = IP = TCP = UDP = None
    sniff = None

from src.packet_parser import build_traffic_dataframe, parse_packets

CAPTURED_PACKETS: List[Any] = []
CAPTURE_STARTED_AT: float | None = None


def start_capture(interface: str = "", packet_limit: int = 5000):
    global CAPTURED_PACKETS, CAPTURE_STARTED_AT
    if sniff is None or IP is None or TCP is None or UDP is None or ICMP is None:
        raise ImportError("Scapy is not available in the current environment.")

    CAPTURED_PACKETS = []
    CAPTURE_STARTED_AT = time.time()

    def packet_handler(packet):
        if packet is None:
            return
        try:
            if not packet.haslayer(IP):
                return
            if packet.haslayer(TCP) or packet.haslayer(UDP) or packet.haslayer(ICMP):
                CAPTURED_PACKETS.append(packet)
                if len(CAPTURED_PACKETS) >= packet_limit:
                    raise KeyboardInterrupt
        except Exception:
            return

    try:
        sniff(iface=interface or None, prn=packet_handler, store=False, stop_filter=lambda p: len(CAPTURED_PACKETS) >= packet_limit)
    except KeyboardInterrupt:
        pass
    except PermissionError:
        raise PermissionError(
            "Live capture was blocked by Windows. Install Npcap with WinPcap API-compatible mode enabled, "
            "then restart the application."
        )
    except OSError as exc:
        raise OSError(f"Unable to access the selected network interface: {exc}")
    except RuntimeError as exc:
        message = str(exc)
        if "winpcap is not installed" in message.lower():
            raise RuntimeError(
                "Windows packet capture is unavailable because Npcap is not installed. "
                "Install Npcap with WinPcap API-compatible mode enabled, then restart the application."
            ) from exc
        raise RuntimeError(f"Scapy could not start live capture: {message}") from exc

    return CAPTURED_PACKETS


def stop_capture():
    return CAPTURED_PACKETS


def packets_to_dataframe(packet_list: List[Any]) -> Any:
    parsed = parse_packets(packet_list)
    return build_traffic_dataframe(parsed)


def capture_summary(packet_list: List[Any]) -> Dict[str, Any]:
    df = packets_to_dataframe(packet_list)
    if df.empty:
        return {"total_packets": 0, "total_bytes": 0, "duration": 0.0}
    return {
        "total_packets": int(len(df)),
        "total_bytes": int(df["length"].sum()),
        "duration": float(max(df["time"].max() - df["time"].min(), 0.0)),
    }
