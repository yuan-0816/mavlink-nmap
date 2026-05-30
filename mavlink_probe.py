#!/usr/bin/env python3
"""
MAVLink GCS UDP Port Detector
用途：偽裝成無人機，發送 MAVLink HEARTBEAT 至 GCS，
      確認 UDP 14550 是否真正開放並回應。

使用方式：
  python3 mavlink_probe.py -t <GCS_IP> [-p <PORT>] [-v]

範例：
  python3 mavlink_probe.py -t 192.168.87.x -p 14550
  python3 mavlink_probe.py -t 192.168.87.x -p 14550 -v

作者：資安檢測用途，請只在授權目標上使用。
"""

import socket
import struct
import argparse
import time
import sys

# ──────────────────────────────────────────
# MAVLink v1 CRC (X.25 / CRC-16-MCRF4XX)
# ──────────────────────────────────────────
def x25crc(data: bytes) -> int:
    crc = 0xFFFF
    for b in data:
        tmp = (b ^ (crc & 0xFF)) & 0xFF
        tmp ^= (tmp << 4) & 0xFF
        crc = ((crc >> 8) ^ (tmp << 8) ^ (tmp << 3) ^ (tmp >> 4)) & 0xFFFF
    return crc


# ──────────────────────────────────────────
# MAVLink v1 HEARTBEAT 封包建構
# ──────────────────────────────────────────
# CRC_EXTRA 值由官方 XML 定義，HEARTBEAT msg_id=0 的 CRC_EXTRA = 50
HEARTBEAT_CRC_EXTRA = 50

def build_mavlink1_heartbeat(
    sysid: int = 1,      # 模擬無人機 system ID (預設 1)
    compid: int = 1,     # 模擬飛控 component ID
    seq: int = 0,
) -> bytes:
    """
    建構 MAVLink v1 HEARTBEAT 封包（模擬 ArduPilot 四旋翼）

    Payload 欄位（依 wire format 排序：大欄位在前）：
      custom_mode   : uint32  = 0
      type          : uint8   = 2  (MAV_TYPE_QUADROTOR)
      autopilot     : uint8   = 3  (MAV_AUTOPILOT_ARDUPILOTMEGA)
      base_mode     : uint8   = 0
      system_status : uint8   = 4  (MAV_STATE_ACTIVE)
      mavlink_version: uint8  = 3
    """
    MSG_ID = 0       # HEARTBEAT
    PAYLOAD_LEN = 9

    payload = struct.pack(
        "<IBBBBB",
        0,   # custom_mode (uint32)
        2,   # type: MAV_TYPE_QUADROTOR
        3,   # autopilot: MAV_AUTOPILOT_ARDUPILOTMEGA
        0,   # base_mode
        4,   # system_status: MAV_STATE_ACTIVE
        3,   # mavlink_version
    )
    assert len(payload) == PAYLOAD_LEN, f"Payload size error: {len(payload)}"

    # CRC 計算範圍：len, seq, sysid, compid, msgid + payload + CRC_EXTRA
    crc_data = bytes([PAYLOAD_LEN, seq, sysid, compid, MSG_ID]) + payload + bytes([HEARTBEAT_CRC_EXTRA])
    crc = x25crc(crc_data)
    crc_lo = crc & 0xFF
    crc_hi = (crc >> 8) & 0xFF

    # 完整封包：0xFE + header(5) + payload(9) + crc(2) = 17 bytes
    packet = bytes([0xFE, PAYLOAD_LEN, seq, sysid, compid, MSG_ID]) + payload + bytes([crc_lo, crc_hi])
    return packet


# ──────────────────────────────────────────
# MAVLink v2 HEARTBEAT 封包建構
# ──────────────────────────────────────────
def build_mavlink2_heartbeat(
    sysid: int = 1,
    compid: int = 1,
    seq: int = 0,
) -> bytes:
    """
    建構 MAVLink v2 HEARTBEAT 封包（用於測試 v2 GCS）
    Header: 0xFD, payload_len(1), incompat_flags(1), compat_flags(1),
            seq(1), sysid(1), compid(1), msgid(3) = 10 bytes
    """
    MSG_ID = 0
    PAYLOAD_LEN = 9

    payload = struct.pack(
        "<IBBBBB",
        0, 2, 3, 0, 4, 3
    )

    incompat_flags = 0x00
    compat_flags = 0x00
    msgid_bytes = struct.pack("<I", MSG_ID)[:3]  # 3-byte little-endian

    header_for_crc = bytes([
        PAYLOAD_LEN, incompat_flags, compat_flags,
        seq, sysid, compid
    ]) + msgid_bytes

    crc_data = header_for_crc + payload + bytes([HEARTBEAT_CRC_EXTRA])
    crc = x25crc(crc_data)
    crc_lo = crc & 0xFF
    crc_hi = (crc >> 8) & 0xFF

    packet = (bytes([0xFD, PAYLOAD_LEN, incompat_flags, compat_flags,
                     seq, sysid, compid]) + msgid_bytes + payload + bytes([crc_lo, crc_hi]))
    return packet


# ──────────────────────────────────────────
# 解析收到的 MAVLink 回應（基本識別）
# ──────────────────────────────────────────
MAV_TYPES = {
    0: "GENERIC", 1: "FIXED_WING", 2: "QUADROTOR", 6: "GCS",
    18: "ONBOARD_CONTROLLER", 27: "ADSB"
}
MAV_AUTOPILOTS = {
    0: "GENERIC", 3: "ARDUPILOTMEGA", 8: "PX4", 12: "INVALID"
}
MAV_STATES = {
    0: "UNINIT", 1: "BOOT", 2: "CALIBRATING", 3: "STANDBY",
    4: "ACTIVE", 5: "CRITICAL", 6: "EMERGENCY", 7: "POWEROFF"
}

def parse_mavlink_response(data: bytes, verbose: bool = False) -> dict | None:
    """解析回應封包，支援 v1(0xFE) 和 v2(0xFD)"""
    if len(data) < 8:
        return None

    result = {}

    if data[0] == 0xFE:  # MAVLink v1
        result["version"] = 1
        payload_len = data[1]
        result["seq"] = data[2]
        result["sysid"] = data[3]
        result["compid"] = data[4]
        result["msgid"] = data[5]
        if len(data) < 6 + payload_len + 2:
            result["error"] = "封包截斷"
            return result
        payload = data[6: 6 + payload_len]

    elif data[0] == 0xFD:  # MAVLink v2
        result["version"] = 2
        payload_len = data[1]
        result["seq"] = data[4]
        result["sysid"] = data[5]
        result["compid"] = data[6]
        msgid = struct.unpack_from("<I", data[7:10] + b"\x00")[0]
        result["msgid"] = msgid
        if len(data) < 10 + payload_len + 2:
            result["error"] = "封包截斷"
            return result
        payload = data[10: 10 + payload_len]
    else:
        result["error"] = f"未知起始字節 0x{data[0]:02X}"
        return result

    if result["msgid"] == 0 and len(payload) >= 9:  # HEARTBEAT
        result["msg_type"] = "HEARTBEAT"
        custom_mode, mav_type, autopilot, base_mode, sys_status, mav_ver = struct.unpack_from("<IBBBBB", payload)
        result["mav_type"] = f"{mav_type} ({MAV_TYPES.get(mav_type, 'UNKNOWN')})"
        result["autopilot"] = f"{autopilot} ({MAV_AUTOPILOTS.get(autopilot, 'UNKNOWN')})"
        result["base_mode"] = base_mode
        result["sys_status"] = f"{sys_status} ({MAV_STATES.get(sys_status, 'UNKNOWN')})"
        result["mav_version"] = mav_ver
        result["custom_mode"] = custom_mode
    else:
        result["msg_type"] = f"MSG_ID={result['msgid']}"

    return result


# ──────────────────────────────────────────
# 主掃描邏輯
# ──────────────────────────────────────────
def probe_gcs(target_ip: str, target_port: int, timeout: float = 3.0,
              retries: int = 3, verbose: bool = False):

    print(f"\n{'='*55}")
    print(f"  MAVLink GCS 偵測 | 目標：{target_ip}:{target_port}/UDP")
    print(f"{'='*55}")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)

    # 同時測試 v1 和 v2
    probes = [
        ("MAVLink v1 HEARTBEAT", build_mavlink1_heartbeat(sysid=1, compid=1, seq=0)),
        ("MAVLink v2 HEARTBEAT", build_mavlink2_heartbeat(sysid=1, compid=1, seq=1)),
    ]

    port_state = "filtered"  # 預設

    for attempt in range(1, retries + 1):
        for probe_name, packet in probes:
            print(f"\n[嘗試 {attempt}/{retries}] 發送 {probe_name} (模擬無人機 sysid=1)")
            if verbose:
                print(f"  RAW HEX: {packet.hex()}")
                print(f"  封包大小: {len(packet)} bytes")

            try:
                sock.sendto(packet, (target_ip, target_port))
                resp_data, resp_addr = sock.recvfrom(1024)

                port_state = "open"
                print(f"\n  ✅  收到回應！來源：{resp_addr[0]}:{resp_addr[1]}")
                print(f"  📦  回應大小：{len(resp_data)} bytes")
                if verbose:
                    print(f"  RAW HEX: {resp_data.hex()}")

                parsed = parse_mavlink_response(resp_data, verbose)
                if parsed:
                    print(f"\n  ┌── MAVLink 解析結果 ──")
                    for k, v in parsed.items():
                        print(f"  │  {k:<18}: {v}")
                    print(f"  └─────────────────────")

                    if parsed.get("sysid") == 255:
                        print("\n  ⚠️  注意：回應 sysid=255，這是標準 GCS 身份識別！")
                break  # 收到回應即停止重試

            except socket.timeout:
                print(f"  ⏱  逾時（{timeout}s），無回應")
            except Exception as e:
                print(f"  ❌  錯誤：{e}")

        if port_state == "open":
            break
        time.sleep(0.5)

    sock.close()

    print(f"\n{'='*55}")
    print(f"  最終判定：UDP {target_port} 狀態 = {port_state.upper()}")
    if port_state == "filtered":
        print("\n  可能原因：")
        print("  1. GCS 尚未連上無人機（未啟動 MAVLink 監聽）")
        print("  2. 防火牆過濾了非預期來源 IP")
        print("  3. GCS 只接受特定 sysid 的來源")
        print("  4. Port 確實存在但需要先建立連線握手")
    print(f"{'='*55}\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="MAVLink GCS UDP 資安檢測探針 - 模擬無人機偵測 GCS 回應"
    )
    parser.add_argument("-t", "--target", required=True, help="目標 GCS IP")
    parser.add_argument("-p", "--port", type=int, default=14550, help="目標 UDP port（預設 14550）")
    parser.add_argument("--timeout", type=float, default=3.0, help="等待逾時秒數（預設 3）")
    parser.add_argument("--retries", type=int, default=3, help="重試次數（預設 3）")
    parser.add_argument("-v", "--verbose", action="store_true", help="顯示原始 HEX 封包")
    args = parser.parse_args()

    probe_gcs(
        target_ip=args.target,
        target_port=args.port,
        timeout=args.timeout,
        retries=args.retries,
        verbose=args.verbose,
    )