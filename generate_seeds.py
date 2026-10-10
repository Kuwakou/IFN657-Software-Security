"""
IFN657-Software-Security/generate_seeds.py
Task 1: seed generator
"""

import struct, os
 
BASE = os.path.dirname(os.path.abspath(__file__))
 
# Each seed goes into its matching target folder under targets/.
FOLDERS = {
    "telemetry": os.path.join(BASE, "targets", "seeds_telemetry"),
    "payload":   os.path.join(BASE, "targets", "seeds_payload"),
    "network":   os.path.join(BASE, "targets", "seeds_network"),
}
for folder in FOLDERS.values():
    os.makedirs(folder, exist_ok=True)
 
def write(name, data: bytes):
    # choose the folder by which target word appears in the file name
    folder = next(f for key, f in FOLDERS.items() if key in name)
    path = os.path.join(folder, name)
    with open(path, "wb") as f:
        f.write(data)
    print(f"  {path:55s} {len(data):4d} bytes")


# target 1: sentinel_telemetry
# Format: key=value pairs, one entry per line.
# Special keys include log_event, stream_multiplier, aux_buffer_request,
# sensor_id_*, and cal_factor_*.
# Other keys are treated as generic entries.
# Keep key and value lengths short to avoid overflowing the parser buffer.

print ("[telemetry]")

# Seed A: tests sensor, calibration, logging, and stream paths. 
telem_a = (
    b"# seed A - calibration & stream profile\n"
    # generic key-value entry
    b"subsystem_mode=standby\n"
    # test the sensor_id * parser path with two different sensor ID
    b"sensor_id_primary=204\n"
    b"sensor_id_secondary=205\n"
    # test the cal_factor_ * parser path with two calibration values
    b"cal_factor_thermal=0.98\n"
    b"cal_factor_optical=1.12\n"
    # test the logging path
    b"log_event=calibration_sweep_start\n"
    # test the stream multiplir path
    b"stream_multiplier=2\n"
)
write("seed_telemetry_a.conf", telem_a)


# Seed B: tests the auxiliary buffer and different sensor/calibration values.

telem_b = (
    b"# seed B - buffer allocation & multi-sensor\n"
    # Generic key-value entry with a different value.
    b"subsystem_mode=active\n"
    # Test the auxiliary buffer allocation path.
    b"aux_buffer_request=256\n"
    # Test the sensor_id_* parser path with another sensor name.
    b"sensor_id_array=307\n"
    # Test the cal_factor_* parser path with another calibration value.
    b"cal_factor_radar=1.44\n"
    # Test the logging path with a different event.
    b"log_event=buffer_reserved\n"
    # Test the stream multiplier path with a different value.
    b"stream_multiplier=8\n"
)
write("seed_telemetry_b.conf", telem_b)

# Seed C: safe-holder profile - same recognised keys, different values/state
telem_c = (
    b"# seed C - safe-hold profile\n"
    # Test a generic subsystem mode entry.
    b"subsystem_mode=safe_hold\n"
    # Test the sensor ID parser path
    b"sensor_id_backup=411\n"
    # Test the calibration factor parser path
    b"cal_factor_gyro=0.87\n"
    #  Test the logging path with a different event
    b"log_event=mode_change_ok\n"
    # Test the stream multiplier path with a value of 1.
    b"stream_multiplier=1\n"
)
write("seed_telemetry_c.conf", telem_c)

# target 2: sentinel_payload
# format: header + binary data
# header: "PAYLOAD_FRAME <w> <h> <d> <label>"
# data size must be exactly w * h * d bytes
# keep the data size <= 1024 bytes to stay within the frame cache
# avoid width 1337 because it triggers the UAF path

print("[payload]")

def payload_frame(w, h, d, label: bytes, fill):
    # calculate the required number of data byte
    n = w * h * d

    # build frame header 
    header = b"PAYLOAD_FRAME %d %d %d %s\n" % (w, h, d, label)
    # generate the binary data
    body = bytes(fill(i) for i in range(n)) if callable(fill) else bytes([fill]) * n
    # return complete frame
    return header + body

# Seed A: small single-plane frame.
# 4 * 4 * 1 = 16 bytes of data.
# depth=1 exercises the single-plane path.
# The label is short and safely below 64 characters.
# The lambda generates simple sequential byte values.

write(
    "seed_payload_a.bin",
    payload_frame(
        4,  #width
        4,  #height
        1,  #depth
        b"IMG_CAL_04", #frame label
        lambda i: i & 0xFF #sequential byte pattern
    )
)

# Seed B: multi-spectral frame.
# 8 * 8 * 3 = 192 bytes of data.
# depth=3 exercises the multi-plane path.
# The label is longer but still below 64 characters.
# The lambda generates a different deterministic byte pattern.
write(
    "seed_payload_b.bin",
    payload_frame(
        8,                          # Width
        8,                          # Height
        3,                          # Depth
        b"MULTISPEC_SCAN_07",       # Frame label
        lambda i: (i * 7) & 0xFF   # Deterministic byte pattern
    )
)

write(
    "seed_payload_c.bin",
    payload_frame(
        16,                          # Width
        16,                          # Height
        1,                          # Depth
        b"RADAR_WIDEBAND_SURVEY_PASS",       # Frame label
        lambda i: (i * 3) & 0xFF   # Deterministic byte pattern
    )
)

# target 3: sentinel_network (binary packet)
# Format: header + payload.
# Header contains magic, packet type, and payload length.
# The magic value must be 0x12345678.
# The length field must match the full payload length.
# Include a trailing NUL because the payload is treated as a C string.
# Keep the payload length greater than 8 bytes for the Type 1 path.
# Type 2 is not used because it causes an intentional buffer overflow.

print("[network]")

# magic value expected by the network parser
MAGIC = 0x12345678

def packet(ptype, payload: bytes):
    # Build the packet header and append the payload.
    return struct.pack("<IHH", MAGIC, ptype, len(payload)) + payload

# Seed A: Type 1 packet containing a normal station status message.
# The trailing NUL safely terminates the payload as a C string.
write(
    "seed_network_a.bin",
    packet(1, b"STATION_STATUS_OK\x00")
)


# Seed B: Type 3 packet containing an emergency failover message.
# Type 3 exercises a different parser branch from Type 1.
# The trailing NUL safely terminates the payload as a C string.
write(
    "seed_network_b.bin",
    packet(3, b"EMERGENCY_FAILOVER\x00")
)

# Seed C: two packets containing status messages
# type 3 and 1 two different parser branches in one imput
# the trailing NUL in each payload safety terminal it as a C string
# comnining both packets tests how the paraser handles consecutive packets

write(
    "seed_network_c.bin",
    packet(3, b"STATUS_A\x00") + packet(1, b"STATUS_B\x00")
)

# All six seeds have now been generated.
print("\nDone. 6 seeds in ./seeds/")
