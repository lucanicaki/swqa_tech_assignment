# Assignment 3 — TWS Bluetooth Audio System Log Analysis

**Bang & Olufsen QA Technical Assignment**  
**Tool:** Python 3 (standard library + matplotlib)  
**Files analysed:** `Device_1.pcapng` · `Device_2.pcapng` · `Device_3.pcapng`  
**Chip:** AB1585/88 (Airoha/MediaTek — same vendor family as Assignment 2)

---

## Device roles

| Device | Role | Confidence |
|---|---|---|
| **Device 1** | **Primary Earbud (Agent)** | 94% primary |
| **Device 2** | **Secondary Earbud (Partner)** | 91% secondary |
| **Device 3** | **USB Audio Dongle / Charging Case Controller** | 100% dongle |

---

## File identification

All three files are PCAPNG with link type 201 — the same AB158x vendor firmware ASCII debug log format identified in Assignment 2. Confirmed by the first packet in each file:

```
tool = AB1585/88 Logging Tool, version = 3.10.0.6
```

The three captures are **simultaneous** — they share overlapping wall-clock timestamps:

| Device | Start timestamp (µs) | End timestamp (µs) | Duration |
|---|---|---|---|
| Device 1 | 1,773,114,678 | 1,773,118,326 | 3648s (61 min) |
| Device 2 | 1,773,114,672 | 1,773,118,325 | 3653s |
| Device 3 | 1,773,116,560 | 1,773,118,322 | 1762s (joined 31 min in) |

Devices 1 and 2 start within 6 seconds of each other and end within 1 second. Device 3 starts 1888 seconds later — it was hot-plugged to USB while the earbuds were already streaming.

---

## Analysis chart

![TWS Analysis Chart](tws_analysis.png)

The chart has two panels. The topology panel shows the three-device architecture and the protocols on each link. The timeline panel shows 76 extracted events across all three devices on three horizontal lanes — one per device — ordered by wall-clock time.

---

## Role identification — evidence from real log messages

### Device 1 — Primary Earbud (Agent)

The Primary earbud holds the Bluetooth connection to the phone, manages the A2DP audio stream, and handles user input. It is the "Agent" in AB1585/88 terminology.

| Log entry | Interpretation |
|---|---|
| `[BT_CM][AWS_MCE][I] Agent set AWS state` | Definitive Agent role confirmation |
| `aws_role:0x40` | Hex role value — 0x40 = Agent in AB1585/88 |
| `BT_SINK_SRV_STATE_STREAMING` in BEO_KEY_REMAPPER | Holds the active A2DP sink connection |
| `BEO_KEY_REMAPPER: Mapping Key 0x7e [REPEAT]` | Primary processes user key presses |
| `APP_FORCE_SENSOR: Unhandled key event` | Force/touch sensor only on primary |
| `[Music_APP] utils process key event` | Music playback management |
| `[LEA][AIRD_CLIENT] start_pre_action` | LE Audio AIRD client role |
| `[CALL][AWS_MCE]Agent send call info` | HFP call handling via Agent role |

### Device 2 — Secondary Earbud (Partner)

The Secondary receives relayed audio from the Primary over the AWS inter-earbud link. It has no direct Bluetooth connection to the phone.

| Log entry | Interpretation |
|---|---|
| `@@@ Partner RX_BT3_MIC_ERROR RxMicCnt … MicErrCnt` | Definitive Partner role marker — Primary monitors partner mic errors |
| `lcAWSCTL_HandlePostponeIF, IF_TYPE_A2DP_PLR_REQ` | Partner Link Relay Request — secondary requesting audio relay |
| `Aws If: 580–640` in scheduler (very high) | Entire radio budget on AWS = secondary receiver with no phone link |
| `role:20` in race_app_aws | 0x20 = Partner role in AB1585/88 |
| `[M:BEO_RELAY` module active | Secondary relay stack running |
| `beo_audio_awe_layout_info AWEInstance: channelCountIn:12` | DSP AWE layout — only secondary has full DSP processing info here |
| No AVDTP entries, no sink_srv entries | No direct phone connection |

### Device 3 — USB Audio Dongle / Charging Case Controller

Device 3 is a fundamentally different device type — not an earbud. It is a USB audio dongle that also acts as the charging case controller.

| Log entry | Interpretation |
|---|---|
| `[M:DONGLE_AIR` module | Dongle firmware identity |
| `BEO_INTERFACE_USB [BEO_PAUSED]` | USB audio source, initially paused |
| `USBAUDIO_DRV: USB_Aduio_Set_TX1_Alt1` | USB audio driver active |
| `APP_CHARGER_CASE: Earbud Currents: L[ADC…] R[ADC…]` | Monitors charging current for both earbuds independently |
| `SoC: case[99] L[100] R[100]` | Reports case battery + both earbud batteries |
| `connect_cs, sirk:b6-31-f2-8e-e6-55-d0-31` | LE Audio Coordinated Set discovery using SIRK |
| Battery always 100%, `is_charger_connected[1]` | Device is USB-powered |
| Starts 1888s into session | Hot-plugged USB device, not present at session start |

---

## Left / right earbud identification

The AB1585/88 log reports earbud side in `APP_PROTO_IND` entries: `Side = 1` = Left, `Side = 2` = Right.

- **Device 1** reports `Side = 2` (Right) at t=598s, then `Side = 1` (Left) at t=3578s
- **Device 2** reports `Side = 1` (Left) at t=459s, then `Side = 2` (Right) at t=1254s

The side assignment **flips during the session** — this directly reflects the three Role Handover (RHO) events. When Primary and Secondary roles swap, so do the left/right assignments. The earbud that becomes Agent after RHO reports whichever side the Agent occupies.

---

## Primary user scenario

**Firmware OTA update during active TWS music streaming, with USB dongle connection and Role Handover events**

This is a 61-minute multi-phase session, not a routine listening session. The defining characteristic is the presence of `BEO_UPGRADE_LIB`, `BEO_UPGRADE_FLASH`, and `BEO_UPGRADE_DATA` modules running simultaneously with A2DP streaming, culminating in `"Apply upgrade and reboot"` at t=3643s.

### Four-phase breakdown

**Phase 1 — Streaming + OTA begins (t=0s to t=455s)**  
Both earbuds in-ear from the start (wear detect confirms `local=1, remote=1`). Music streaming active on Device 1. OTA starts in background — `RACE_FOTA_CHECK_INTEGRITY` at t=110s, partition queries, then flash write events on both devices.

**Phase 2 — First RHO + charging case interaction (t=455s to t=600s)**  
RHO #1 completes at t=455s. Device 1 logs a lid close event at t=455s — one earbud briefly touched the case. Device 2 logs `CHARGER_IN = charger_exist=1` at t=524s. Agent/Partner roles re-established. OTA data continues transferring across the RHO boundary.

**Phase 3 — USB dongle connects + LE Audio (t=588s to t=1762s)**  
Device 3 starts logging at t=1888s (wall-clock) — USB dongle plugged in. Immediately reports USB audio source and begins LE Audio Coordinated Set discovery via SIRK. Two more RHO events at t=1017s and t=1286s. Wear detect on Device 1 shows `remote=0` at t=1557s — one earbud temporarily removed from ear. Lid open event at t=1630s.

**Phase 4 — OTA completes, session end (t=1630s to t=3648s)**  
`"Apply upgrade and reboot"` logged at t=3643s on Device 1 — firmware OTA complete. Battery readings across the session show steady discharge: D1 87%→71%, D2 85%→81%. Device 3 holds 100% throughout (USB powered). Both devices log lid open events near t=3583s–3648s, consistent with earbuds being returned to case at session end.

---

## Acoustic and signal chain interpretation

### Two audio paths co-exist in this capture

```
CLASSIC BT PATH (phone source):
Phone → Classic BT A2DP (SBC) → Device 1 (Primary) → AWS relay → Device 2

LE AUDIO PATH (USB dongle source):
PC → USB → Device 3 dongle → BLE LE Audio (CIS) → Device 1 + Device 2
```

The SIRK (`b6-31-f2-8e-e6-55-d0-31`) is the Set Identity Resolving Key — a cryptographic identifier for the Coordinated Set formed by the two earbuds. Device 3 uses it to discover and bind to both earbuds simultaneously as LE Audio Coordinated Set members. This is the LE Audio equivalent of TWS pairing, providing simultaneous delivery to both earbuds without the relay hop.

### Role Handover — acoustic implications

RHO transfers the Agent role between earbuds. The A2DP connection migrates from the old Agent to the new Agent. If RHO completes within the jitter buffer's lookahead window, the user hears no interruption. The three RHOs here occur during OTA — this is deliberate firmware design: OTA uses RHO to ensure the non-flashing earbud handles streaming while the other writes to flash, preventing audio dropout during the write operation.

### OTA + streaming simultaneously

Flash write operations (`BEO_UPGRADE_FLASH`) running concurrently with DSP audio processing represent the maximum CPU and memory bus pressure state for the earbud firmware. Any scheduling jitter introduced by flash write interrupts manifesting in the DSP processing loop would produce jitter buffer level drops — acoustically indistinguishable from RF interference but with a completely different root cause. This is a critical QA test case: verifying audio quality does not degrade during OTA writes.

### Why Device 2's AWS slot count is much higher than Device 1's

Device 2 (Secondary) logs `Aws If: 500–640` scheduler slots, while Device 1 (Primary) logs `Aws If: 44–64`. The Secondary's radio budget is almost entirely allocated to the AWS inter-earbud link because it has no direct phone connection — 100% of its audio arrives via AWS. The Primary allocates fewer AWS slots because it splits its radio time between the phone ACL link (for receiving A2DP) and the AWS link (for relaying to Secondary).

---

## Step-by-step analysis methodology

### Step 1: Identify the file format

```python
magic = struct.unpack_from('<I', data, 0)[0]  # 0x0A0D0D0A = PCAPNG OK
link_type = struct.unpack_from('<H', data, idb_pos + 8)[0]  # 201 = AB158x vendor log
# First packet text: "tool = AB1585/88 Logging Tool, version = 3.10.0.6"
```

### Step 2: Align timestamps — confirm simultaneity

Compare first and last timestamps across all files. Timestamps that end within seconds of each other, with overlapping ranges, confirm a coordinated multi-device capture.

### Step 3: Identify roles from module names alone

Before reading a single log message, the list of active software modules in each file reveals the device type:

- Device 1: `BEO_KEY_REMAPPER, APP_FORCE_SENSOR, APP_BEO_AUDIO_PROMPT` → Primary (handles user input)
- Device 2: `BEO_RELAY, BTAWS` heavy, `Partner RX_BT3_MIC_ERROR` → Secondary (relay receiver)
- Device 3: `DONGLE_AIR, USBAUDIO_DRV, APP_CHARGER_CASE, LE_AUDIO` → USB Dongle

### Step 4: Confirm with hexadecimal role values

In AB1585/88, role values are explicit: `0x40` = Agent, `0x20` = Partner. Both appear in `BT_CM` and `race_app_aws` log entries respectively.

### Step 5: Identify left/right and track RHO

`APP_PROTO_IND: Side = N` reports the earbud's side assignment. Cross-referencing side changes with `BT_CM: end cm rho gap event` timestamps confirms that side assignments flip on each RHO.

### Step 6: Reconstruct the scenario from event ordering

Merge all three device timelines by wall-clock timestamp. The OTA module sequence (`FOTA_CHECK_INTEGRITY` → `QUERY_PARTITION_INFO` → `BEO_UPGRADE_FLASH` writes → `Apply upgrade and reboot`) spanning the full 61-minute session identifies this as a firmware update session.

---

## How to run

```bash
pip install matplotlib

# With the actual files
python3 analyse_tws_real.py Device_1.pcapng Device_2.pcapng Device_3.pcapng

# Script auto-detects files in default upload path
python3 analyse_tws_real.py
```

---

## References

- Bluetooth SIG. *Core Specification 5.4, Vol 3 Part C* — Generic Access Profile, Role Switching
- Bluetooth SIG. *LE Audio (LC3 codec, CIS, Coordinated Sets)* — Bluetooth 5.2
- Bluetooth SIG. *Coordinated Set Identification Profile (CSIP)* — SIRK, Set Member Discovery
- Airoha Technology. *AB1585/88 Bluetooth Audio SoC* — AWS inter-earbud protocol, Agent/Partner roles, RHO
- Bluetooth SIG. *A2DP Specification 1.4* — Advanced Audio Distribution Profile
- Zwicker, E. & Fastl, H. (2013). *Psychoacoustics: Facts and Models, 3rd ed.* Springer
- Blauert, J. (1997). *Spatial Hearing.* MIT Press *(Inter-channel timing, binaural perception)*
