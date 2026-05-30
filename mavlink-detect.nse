local nmap = require "nmap"
local shortport = require "shortport"
local stdnse = require "stdnse"
local string = require "string"
local table = require "table"

description = [[
Detects a MAVLink Ground Control Station (GCS) or autopilot endpoint by
impersonating a drone.

Nmap's stock UDP version detection reports MAVLink ports (e.g. 14550/udp) as
"open|filtered" because the service is silent until it receives a correctly
framed MAVLink message. It never answers Nmap's generic/empty UDP probes, so
Nmap cannot tell "open but quiet" from "filtered".

This script sends a valid MAVLink HEARTBEAT (msg_id 0) -- first as MAVLink v1
(0xFE) and then as v2 (0xFD) -- exactly as a real flight controller would, then
reads and decodes the reply: protocol version, system id, component id and
message id. A reply at all proves the port is OPEN; a reply with system id 255
identifies the peer as a Ground Control Station.

The probe payloads are fixed, valid HEARTBEATs (sysid=1, compid=1,
MAV_TYPE_QUADROTOR, MAV_AUTOPILOT_ARDUPILOTMEGA, MAV_STATE_ACTIVE) with
correct X.25/CRC-16-MCRF4XX checksums.

Authorized security testing only. Sending HEARTBEATs to a live GCS that is
controlling an airborne vehicle can influence its connection state -- do not
run this against operational systems in flight.
]]

---
-- @usage
-- nmap -sU -p 14550 --script mavlink-detect <target>
-- nmap -sU -p 14550 --script mavlink-detect --script-args 'mavlink-detect.timeout=5' <target>
--
-- @args mavlink-detect.timeout  Seconds to wait for a reply per probe (default 3)
--
-- @output
-- PORT      STATE SERVICE
-- 14550/udp open  mavlink
-- | mavlink-detect:
-- |   MAVLink version: 1
-- |   system id: 255 (Ground Control Station)
-- |   component id: 190
-- |   message id: 76
-- |_  port state: OPEN (live MAVLink endpoint replied)

author = "Drone security assessment"
license = "Same as Nmap--See https://nmap.org/book/man-legal.html"
categories = {"discovery", "version", "safe"}

-- ---------------------------------------------------------------------------
-- Fixed probe packets (verified, CRC-correct). Generated with sysid=1,
-- compid=1, seq=0, HEARTBEAT(type=QUADROTOR, ap=ARDUPILOTMEGA, ACTIVE).
-- v1 = FE 09 00 01 01 00 | 00000000 02 03 00 04 03 | D0 14
-- ---------------------------------------------------------------------------
local HEARTBEAT_V1 = "\xfe\x09\x00\x01\x01\x00\x00\x00\x00\x00\x02\x03\x00\x04\x03\xd0\x14"
local HEARTBEAT_V2 = "\xfd\x09\x00\x00\x00\x01\x01\x00\x00\x00\x00\x00\x00\x00\x02\x03\x00\x04\x03\x4a\xd7"

local MAV_TYPES = {
  [0]="GENERIC", [1]="FIXED_WING", [2]="QUADROTOR", [3]="COAXIAL",
  [4]="HELICOPTER", [6]="GCS", [10]="GROUND_ROVER", [11]="SURFACE_BOAT",
  [12]="SUBMARINE", [18]="ONBOARD_CONTROLLER", [27]="ADSB",
}
local MAV_AUTOPILOTS = {
  [0]="GENERIC", [3]="ARDUPILOTMEGA", [8]="PX4", [12]="INVALID",
}
local MAV_STATES = {
  [0]="UNINIT", [1]="BOOT", [2]="CALIBRATING", [3]="STANDBY",
  [4]="ACTIVE", [5]="CRITICAL", [6]="EMERGENCY", [7]="POWEROFF",
}

-- Decode a raw MAVLink frame far enough to identify the peer.
local function parse_mavlink(data)
  if not data or #data < 8 then return nil end
  local magic = data:byte(1)
  local r, payload, plen = {}, nil, nil

  if magic == 0xFE then           -- MAVLink v1
    r.version = 1
    plen      = data:byte(2)
    r.seq     = data:byte(3)
    r.sysid   = data:byte(4)
    r.compid  = data:byte(5)
    r.msgid   = data:byte(6)
    payload   = data:sub(7, 6 + plen)
  elseif magic == 0xFD then       -- MAVLink v2
    r.version = 2
    plen      = data:byte(2)
    r.seq     = data:byte(5)
    r.sysid   = data:byte(6)
    r.compid  = data:byte(7)
    r.msgid   = data:byte(8) + data:byte(9) * 256 + data:byte(10) * 65536
    payload   = data:sub(11, 10 + plen)
  else
    return { unknown = string.format("0x%02X", magic) }
  end

  -- Decode HEARTBEAT body if present (msg_id 0, 9-byte payload)
  if r.msgid == 0 and payload and #payload >= 9 then
    local custom_mode, mtype, ap, base, status, ver = string.unpack("<I4BBBBB", payload)
    r.heartbeat = {
      mav_type      = string.format("%d (%s)", mtype, MAV_TYPES[mtype] or "UNKNOWN"),
      autopilot     = string.format("%d (%s)", ap, MAV_AUTOPILOTS[ap] or "UNKNOWN"),
      system_status = string.format("%d (%s)", status, MAV_STATES[status] or "UNKNOWN"),
      base_mode     = base,
      mavlink_ver   = ver,
      custom_mode   = custom_mode,
    }
  end
  return r
end

portrule = shortport.port_or_service(
  {14550, 14551, 14552, 14555, 14556, 14560, 5760},
  "mavlink",
  {"udp", "tcp"}
)

action = function(host, port)
  local timeout = (tonumber(stdnse.get_script_args(SCRIPT_NAME .. ".timeout")) or 3) * 1000

  local probes = {
    { name = "MAVLink v1", data = HEARTBEAT_V1 },
    { name = "MAVLink v2", data = HEARTBEAT_V2 },
  }

  for _, p in ipairs(probes) do
    local sock = nmap.new_socket()
    sock:set_timeout(timeout)

    local ok = sock:connect(host, port, port.protocol)
    if ok then
      ok = sock:send(p.data)
      if ok then
        local status, resp = sock:receive()
        sock:close()

        if status and resp and #resp > 0 then
          stdnse.debug1("Reply to %s: %s", p.name, stdnse.tohex(resp))
          local m = parse_mavlink(resp)

          -- Mark the port as genuinely open + name the service for -sV output.
          port.version = port.version or {}
          port.version.name = "mavlink"
          if m and m.sysid == 255 then
            port.version.product = "MAVLink ground control station"
            port.version.extrainfo = "sysid 255"
          else
            port.version.product = "MAVLink endpoint"
          end
          nmap.set_port_version(host, port, "hardmatched")
          if port.state == "open|filtered" then
            nmap.set_port_state(host, port, "open")
          end

          local out = stdnse.output_table()
          if m and m.version then
            out["MAVLink version"] = m.version
            if m.sysid == 255 then
              out["system id"] = "255 (Ground Control Station)"
            else
              out["system id"] = m.sysid
            end
            out["component id"] = m.compid
            out["message id"]   = m.msgid
            if m.heartbeat then
              out["heartbeat"] = m.heartbeat
            end
          elseif m and m.unknown then
            out["note"] = "non-MAVLink reply, first byte " .. m.unknown
          end
          out["port state"] = "OPEN (live MAVLink endpoint replied to " .. p.name .. ")"
          out["raw reply (hex)"] = stdnse.tohex(resp)
          return out
        end
      end
    end
    if sock then sock:close() end
  end

  return nil  -- no reply: leave Nmap's open|filtered verdict untouched
end
