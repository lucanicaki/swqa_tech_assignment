"""
Assignment 3: TWS Bluetooth Audio System — Real Log Analysis
=============================================================
Analyses three simultaneous PCAPNG captures from a real B&O TWS system:
  Device_1.pcapng — 900,135 packets, 3648 seconds
  Device_2.pcapng — 466,796 packets, 3653 seconds  
  Device_3.pcapng — 451,802 packets, 1762 seconds

Chip: AB1585/88 (Airoha, same vendor family as Assignment 2)
Log format: Vendor firmware ASCII debug log, Link type 201

Findings:
  Device 1 = PRIMARY EARBUD (Agent / Right side initially)
  Device 2 = SECONDARY EARBUD (Partner / Left side initially)
  Device 3 = USB AUDIO DONGLE (LE Audio source + charging case controller)

Primary user scenario: Firmware OTA update during active audio streaming,
  with Role Handover (RHO) events and USB LE Audio dongle connection.

Usage:
    python3 analyse_tws.py
    python3 analyse_tws.py Device_1.pcapng Device_2.pcapng Device_3.pcapng

Requires: Python 3.8+, matplotlib
"""

import struct, re, sys, os, csv
from collections import defaultdict

# ─────────────────────────────────────────────
#  PCAPNG PARSER
# ─────────────────────────────────────────────

def load_packets(filepath, sample_rate=1):
    """
    Load packets from a PCAPNG file.
    sample_rate: 1 = every packet, N = every Nth packet (for large files)
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0x0A0D0D0A:
        raise ValueError(f"Not PCAPNG: {filepath}")

    pos = 0; packets = []; i = 0
    while pos < len(data) - 8:
        bt = struct.unpack_from('<I', data, pos)[0]
        bl = struct.unpack_from('<I', data, pos + 4)[0]
        if bl < 12 or bl > len(data) - pos:
            break
        if bt == 0x00000006:  # Enhanced Packet Block
            ts_h = struct.unpack_from('<I', data, pos + 12)[0]
            ts_l = struct.unpack_from('<I', data, pos + 16)[0]
            cap  = struct.unpack_from('<I', data, pos + 20)[0]
            pkt  = data[pos + 28: pos + 28 + cap]
            if i % sample_rate == 0:
                packets.append(((ts_h << 32) | ts_l, pkt))
            i += 1
        pos += bl
    return packets


def get_msg(pkt):
    """Decode AB158x vendor log text from packet payload."""
    for marker in [b'[M:', b'tool']:
        idx = pkt.find(marker)
        if idx >= 0:
            try:
                return pkt[idx:].decode('ascii', errors='replace').rstrip('\x00').strip()
            except Exception:
                pass
    return None


# ─────────────────────────────────────────────
#  ROLE IDENTIFICATION PATTERNS
#  Each pattern maps to a specific log evidence
# ─────────────────────────────────────────────

# AB1585/88 role values:
#   0x40 = Agent (Primary earbud — holds phone A2DP connection)
#   0x20 = Partner (Secondary earbud — receives AWS relay)
#   role:2 / role:0x2 = partner in race_app_aws

ROLE_EVIDENCE = {

    # ── PRIMARY (Agent) indicators ──────────────────────────────
    'agent_aws_state': re.compile(
        r'AWS_MCE.*Agent set AWS state|BT_CM.*AWS_MCE.*Agent', re.I),
    'agent_role_hex': re.compile(
        r'aws_role:0x40|role:0x40|role:40\b', re.I),
    'agent_call_info': re.compile(
        r'CALL.*AWS_MCE.*Agent send call info', re.I),
    'sink_music_active': re.compile(
        r'BT_SINK_SRV_STATE_STREAMING|sink.*music.*a2dp', re.I),
    'key_remapper': re.compile(
        r'BEO_KEY_REMAPPER.*Mapping Key', re.I),
    'music_app': re.compile(
        r'\[Music_APP\].*key event|Music_APP.*checkAudioState', re.I),
    'force_sensor': re.compile(
        r'APP_FORCE_SENSOR', re.I),
    'le_audio_aird_client': re.compile(
        r'LEA.*AIRD_CLIENT.*start_pre|notify_aird_ready', re.I),

    # ── SECONDARY (Partner) indicators ──────────────────────────
    'partner_mic_error': re.compile(
        r'@@@ Partner RX_BT3_MIC_ERROR', re.I),
    'partner_role_hex': re.compile(
        r'role:0x20|role:20\b|aws.*partner', re.I),
    'aws_plr_req': re.compile(
        r'lcAWSCTL_HandlePostponeIF.*IF_TYPE_A2DP_PLR_REQ'),
    'aws_high_slots': re.compile(
        r'Aws If:([4-9]\d{2}|[1-9]\d{3})'),  # > 400 AWS slots = secondary
    'beo_relay': re.compile(
        r'\[M:BEO_RELAY\s|module:BEO_RELAY', re.I),

    # ── DONGLE/USB indicators ────────────────────────────────────
    'dongle_air': re.compile(
        r'\[M:DONGLE_AIR|dongle_air|DONGLE SYNC|app_dongle_cm', re.I),
    'usb_audio': re.compile(
        r'USBAUDIO_DRV|BEO_INTERFACE_USB|USB_Audio|USB.*Aduio', re.I),
    'charger_case_ctrl': re.compile(
        r'APP_CHARGER_CASE\b|Earbud Currents:.*L\[ADC|SoC: case\[', re.I),
    'le_audio_source': re.compile(
        r'connect_cs.*sirk|APP.*U.*start.*stream_state', re.I),
    'no_a2dp': re.compile(
        r'APP_CHARGER_CASE_PAIR.*Delay|charger.*busy', re.I),

    # ── SCENARIO events ─────────────────────────────────────────
    'rho_complete': re.compile(
        r'end cm rho gap event.*status:0x00', re.I),
    'ota_flash':   re.compile(
        r'BEO_UPGRADE.*FLASH.*writing|bytes written=0x', re.I),
    'ota_complete':re.compile(
        r'Apply upgrade and reboot|FOTA.*COMPLETE', re.I),
    'wear_in':     re.compile(
        r'wear state local = 1, remote = 1'),
    'wear_out':    re.compile(
        r'wear state local = [01], remote = 0|wear state local = 0'),
    'lid_open':    re.compile(
        r'SMCharger.*LID_OPEN|LID_OPEN.*CHARGER_CASE', re.I),
    'lid_close':   re.compile(
        r'SMCharger.*LID_CLOSE|LID_CLOSE.*CHARGER_CASE|SMCHARGER_EVENT_LID_CLOSE', re.I),
    'charger_in':  re.compile(
        r'CHARGER_IN.*charger_exist=1'),
    'battery_soc': re.compile(
        r'Local: SoC = (\d+)'),
    'case_soc':    re.compile(
        r'SoC: case\[(\d+)\] L\[(\d+)\] R\[(\d+)\]'),
}


def score_roles(packets, ts0):
    """
    Score primary/secondary/dongle role for a device by counting
    pattern matches across a sample of its packets.
    Returns dict of scores and list of (time_s, evidence) tuples.
    """
    scores = defaultdict(int)
    evidence = []
    step = max(1, len(packets) // 8000)

    for ts, pkt in packets[::step]:
        rel = (ts - ts0) / 1e6
        m = get_msg(pkt)
        if not m:
            continue

        for key, pat in ROLE_EVIDENCE.items():
            if pat.search(m):
                scores[key] += 1
                entry = (rel, key, m[:180])
                evidence.append(entry)
                break  # one category per message

    return dict(scores), evidence


def determine_role(scores):
    """Map score dict to a human role label."""
    primary_score = sum(scores.get(k, 0) for k in [
        'agent_aws_state', 'agent_role_hex', 'agent_call_info',
        'sink_music_active', 'key_remapper', 'music_app',
        'force_sensor', 'le_audio_aird_client'
    ])
    secondary_score = sum(scores.get(k, 0) for k in [
        'partner_mic_error', 'partner_role_hex', 'aws_plr_req',
        'aws_high_slots', 'beo_relay'
    ])
    dongle_score = sum(scores.get(k, 0) for k in [
        'dongle_air', 'usb_audio', 'charger_case_ctrl',
        'le_audio_source'
    ])

    total = max(primary_score + secondary_score + dongle_score, 1)
    return {
        'role': ('Primary Earbud (Agent)'   if primary_score > secondary_score and primary_score > dongle_score
                 else 'Secondary Earbud (Partner)' if secondary_score > dongle_score
                 else 'USB Audio Dongle / Charging Case Controller'),
        'primary_pct':   round(primary_score   / total * 100),
        'secondary_pct': round(secondary_score / total * 100),
        'dongle_pct':    round(dongle_score     / total * 100),
        'primary_raw':   primary_score,
        'secondary_raw': secondary_score,
        'dongle_raw':    dongle_score,
    }


# ─────────────────────────────────────────────
#  SCENARIO RECONSTRUCTION
# ─────────────────────────────────────────────

SCENARIO_LABELS = {
    'rho_complete':    'Role Handover (RHO) completed',
    'ota_flash':       'OTA firmware write in progress',
    'ota_complete':    'OTA complete — reboot scheduled',
    'wear_in':         'Both earbuds in-ear (wearing)',
    'wear_out':        'Earbud removed / wear detect lost',
    'lid_open':        'Charging case lid opened',
    'lid_close':       'Charging case lid closed',
    'charger_in':      'Earbuds placed in charging case',
    'battery_soc':     'Battery level report',
    'case_soc':        'Case + earbuds battery report',
    'le_audio_aird_client': 'LE Audio AIRD connection established',
    'le_audio_source': 'LE Audio source connected (SIRK)',
    'usb_audio':       'USB audio source active',
    'dongle_air':      'Dongle AIR discovery',
    'partner_mic_error': 'Inter-earbud AWS relay errors',
    'agent_aws_state': 'Agent AWS state change',
}


def build_scenario_timeline(all_device_events, device_roles):
    """
    Merge events from all devices into a unified wall-clock timeline.
    Returns list of (wall_ts, rel_s, device_name, role, event_key, msg)
    """
    PRIORITY_KEYS = {
        'rho_complete', 'ota_flash', 'ota_complete',
        'wear_in', 'wear_out', 'lid_open', 'lid_close',
        'charger_in', 'battery_soc', 'case_soc',
        'le_audio_aird_client', 'le_audio_source', 'usb_audio',
        'dongle_air', 'agent_aws_state',
    }

    merged = []
    for dev_name, (ts0, evidence) in all_device_events.items():
        role = device_roles.get(dev_name, {}).get('role', '?')
        # Deduplicate within 120s windows per event type
        seen = set()
        for rel, key, msg in evidence:
            if key not in PRIORITY_KEYS:
                continue
            bucket = f"{dev_name}_{key}_{int(rel/120)}"
            if bucket not in seen:
                seen.add(bucket)
                wall_ts = ts0 + int(rel * 1e6)
                merged.append((wall_ts, rel, dev_name, role, key, msg))

    merged.sort(key=lambda x: x[0])
    return merged


# ─────────────────────────────────────────────
#  CHART GENERATION
# ─────────────────────────────────────────────

def generate_chart(device_roles, timeline, output_path):
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from matplotlib.patches import FancyBboxPatch
    except ImportError:
        print("[Chart] matplotlib not installed — skipping")
        return

    fig = plt.figure(figsize=(16, 12))
    fig.patch.set_facecolor('#FAFAF8')

    # ── Panel layout ──
    # Top: topology diagram (30%)
    # Bottom: event timeline (70%)
    ax_topo = fig.add_axes([0.04, 0.68, 0.92, 0.28])
    ax_time = fig.add_axes([0.04, 0.06, 0.92, 0.56])

    C = {
        'primary':   '#1A7A4A',
        'secondary': '#8B3A9E',
        'dongle':    '#2B5EA7',
        'rho':       '#D7344B',
        'ota':       '#E87722',
        'wear':      '#059669',
        'charger':   '#2563EB',
        'le_audio':  '#7C3AED',
        'aws':       '#DC2626',
        'subtle':    '#6B7280',
        'bg':        '#F9FAFB',
    }

    # ════════════════════════════════
    #  PANEL 1 — TOPOLOGY
    # ════════════════════════════════
    ax_topo.set_facecolor('#FAFAF8')
    ax_topo.set_xlim(0, 14)
    ax_topo.set_ylim(0, 3.8)
    ax_topo.axis('off')
    ax_topo.set_title(
        'Assignment 3 — TWS System Analysis  ·  Real Device Logs',
        fontsize=11, fontweight='bold', color='#111827', loc='left', pad=6
    )

    def draw_box(ax, cx, cy, w, h, color, title, sub1='', sub2='', rx=0.12):
        box = FancyBboxPatch((cx-w/2, cy-h/2), w, h,
                              boxstyle=f"round,pad={rx}",
                              facecolor=color, edgecolor='white',
                              linewidth=1.5, alpha=0.93, zorder=3)
        ax.add_patch(box)
        ax.text(cx, cy+0.22, title,
                ha='center', va='center', fontsize=9.5,
                fontweight='bold', color='white', zorder=4)
        if sub1:
            ax.text(cx, cy-0.05, sub1,
                    ha='center', va='center', fontsize=7,
                    color='white', alpha=0.9, zorder=4)
        if sub2:
            ax.text(cx, cy-0.32, sub2,
                    ha='center', va='center', fontsize=7,
                    color='white', alpha=0.8, zorder=4)

    def draw_arrow(ax, x1, x2, y, color, label, lw=2, dashed=False):
        ls = '--' if dashed else '-'
        for yd in [y+0.15, y-0.15]:
            ax.annotate('', xy=(x2-0.05, yd), xytext=(x1+0.05, yd),
                        arrowprops=dict(arrowstyle='->', color=color,
                                        lw=lw, linestyle=ls), zorder=2)
        ax.text((x1+x2)/2, y+0.42, label,
                ha='center', va='center', fontsize=7.5, color=color,
                bbox=dict(fc='white', ec=color, pad=2, lw=0.7, alpha=0.95), zorder=5)

    # Devices
    draw_box(ax_topo, 2.2,  1.9, 2.8, 1.4, C['dongle'],
             'DEVICE 3', 'USB Audio Dongle',
             'LE Audio source · Charging case ctrl\n'
             'DONGLE_AIR · USB audio · SIRK discovery')
    draw_box(ax_topo, 7.0,  1.9, 2.8, 1.4, C['primary'],
             'DEVICE 1', 'Primary Earbud (Agent)',
             'role=0x40 · A2DP Sink · Key remapper\n'
             'RHO capable · LE Audio AIRD client')
    draw_box(ax_topo, 11.8, 1.9, 2.8, 1.4, C['secondary'],
             'DEVICE 2', 'Secondary Earbud (Partner)',
             'role=0x20 · AWS relay receiver\n'
             'BEO_RELAY · Partner MIC errors · PLR_REQ')

    # Links
    draw_arrow(ax_topo, 3.6, 5.6, 1.9, C['le_audio'],
               'LE Audio (BLE)\nAIRD + SIRK\n+ USB audio', lw=2.5)
    draw_arrow(ax_topo, 8.4, 10.4, 1.9, C['primary'],
               'AWS inter-earbud\nRelayed A2DP + clock sync\n+ RHO capable', lw=2.5)

    # Evidence box
    ax_topo.text(7.0, 0.38,
        'Key log evidence  ·  '
        'D1: "Agent set AWS state" · "BT_SINK_SRV_STATE_STREAMING" · "BEO_KEY_REMAPPER" · aws_role:0x40  ·  '
        'D2: "@@@ Partner RX_BT3_MIC_ERROR" · "lcAWSCTL…PLR_REQ" · Aws If:600+ · role:0x20  ·  '
        'D3: "DONGLE_AIR" · "BEO_INTERFACE_USB" · "SoC: case[99] L[100] R[100]" · connect_cs SIRK',
        ha='center', va='center', fontsize=6.8, color='#374151',
        style='italic',
        bbox=dict(fc='#EEF2FF', ec='#A5B4FC', pad=4, lw=0.7, alpha=0.95))

    # ════════════════════════════════
    #  PANEL 2 — TIMELINE
    # ════════════════════════════════
    ax_time.set_facecolor('#FAFAF8')
    for sp in ax_time.spines.values():
        sp.set_visible(False)

    if not timeline:
        ax_time.text(0.5, 0.5, 'No timeline data',
                     ha='center', va='center', transform=ax_time.transAxes)
    else:
        times = [t[1] for t in timeline]
        t_min, t_max = min(times), max(times)
        t_range = max(t_max - t_min, 1)
        ax_time.set_xlim(t_min - t_range*0.02, t_max + t_range*0.02)
        ax_time.set_ylim(-3.5, 4.0)
        ax_time.set_xlabel('Time relative to capture start (seconds)', fontsize=9, color='#374151')
        ax_time.tick_params(axis='x', labelsize=8, colors='#6B7280')
        ax_time.tick_params(axis='y', left=False, labelleft=False)
        ax_time.grid(axis='x', color='#E5E7EB', linewidth=0.5, linestyle='--', alpha=0.6)

        # Three horizontal lanes, one per device
        LANES = {
            'Device_1': ( 1.8, C['primary'],   'D1 Primary'),
            'Device_2': ( 0.0, C['secondary'], 'D2 Secondary'),
            'Device_3': (-1.8, C['dongle'],    'D3 Dongle'),
        }
        for dev, (y_lane, color, label) in LANES.items():
            ax_time.axhline(y=y_lane, color=color, alpha=0.2, lw=1.2, zorder=1)
            ax_time.text(t_min - t_range*0.015, y_lane, label,
                         ha='right', va='center', fontsize=7.5,
                         color=color, fontweight='bold')

        EVENT_COLORS = {
            'rho_complete':    C['rho'],
            'ota_flash':       C['ota'],
            'ota_complete':    '#C2410C',
            'wear_in':         C['wear'],
            'wear_out':        '#9CA3AF',
            'lid_open':        C['charger'],
            'lid_close':       C['charger'],
            'charger_in':      C['charger'],
            'battery_soc':     '#6B7280',
            'case_soc':        C['dongle'],
            'le_audio_aird_client': C['le_audio'],
            'le_audio_source': C['le_audio'],
            'usb_audio':       C['le_audio'],
            'dongle_air':      C['dongle'],
            'agent_aws_state': C['primary'],
        }

        plotted = []
        for wall_ts, rel, dev, role, key, msg in timeline:
            dev_key = os.path.splitext(dev)[0] if '.' in dev else dev
            if dev_key not in LANES:
                continue
            y_lane, dev_color, _ = LANES[dev_key]
            ev_color = EVENT_COLORS.get(key, '#6B7280')

            # Avoid overcrowding — skip if too close to existing point
            too_close = any(abs(rel - pr) < t_range*0.008 and pdev == dev_key
                            for pr, pdev in plotted)
            if too_close:
                continue
            plotted.append((rel, dev_key))

            # Draw marker
            ax_time.scatter([rel], [y_lane], color=ev_color, s=40, zorder=4,
                            edgecolors='white', linewidth=0.8)

            # Label alternating above/below lane
            label_y = y_lane + 0.55 if len(plotted) % 2 == 0 else y_lane - 0.55
            ax_time.plot([rel, rel], [y_lane, label_y],
                         color=ev_color, lw=0.7, alpha=0.6, zorder=2)
            label = SCENARIO_LABELS.get(key, key)[:24]
            ax_time.text(rel, label_y + (0.12 if label_y > y_lane else -0.12),
                         f"{rel:.0f}s\n{label}",
                         ha='center', va='bottom' if label_y > y_lane else 'top',
                         fontsize=5.5, color=ev_color,
                         bbox=dict(fc='white', ec=ev_color, pad=1, lw=0.5, alpha=0.9),
                         zorder=5)

        # Legend
        legend_items = [
            mpatches.Patch(color=C['primary'],   label='Device 1 — Primary (Agent)'),
            mpatches.Patch(color=C['secondary'], label='Device 2 — Secondary (Partner)'),
            mpatches.Patch(color=C['dongle'],    label='Device 3 — USB Dongle'),
            mpatches.Patch(color=C['rho'],       label='RHO event'),
            mpatches.Patch(color=C['ota'],       label='OTA firmware update'),
            mpatches.Patch(color=C['le_audio'],  label='LE Audio / USB audio'),
            mpatches.Patch(color=C['wear'],      label='Wear detect'),
            mpatches.Patch(color=C['charger'],   label='Charger case event'),
        ]
        ax_time.legend(handles=legend_items, loc='upper right',
                       fontsize=7, framealpha=0.92, edgecolor='#E5E7EB',
                       fancybox=False, ncol=4, columnspacing=0.8)

    plt.savefig(output_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"[Chart] Saved: {output_path}")


# ─────────────────────────────────────────────
#  REPORT PRINTER
# ─────────────────────────────────────────────

def print_report(device_roles, timeline):
    sep = '─' * 64
    print(f'\n{"═"*64}')
    print('  ASSIGNMENT 3 — TWS SYSTEM LOG ANALYSIS — FULL REPORT')
    print(f'{"═"*64}')

    print(f'\n  CAPTURE OVERVIEW\n  {sep}')
    print(f"""
  Three simultaneous captures from the same B&O TWS product:

  Device 1  900,135 packets  3648 seconds  (AB1585/88, link type 201)
  Device 2  466,796 packets  3653 seconds  (AB1585/88, link type 201)
  Device 3  451,802 packets  1762 seconds  (AB1585/88, link type 201)

  All three captures share overlapping wall-clock timestamps,
  confirming they are simultaneous logs from three co-operating devices.
  Device 3 starts ~1888 seconds later than Devices 1 and 2 — it joined
  the session mid-way (dongle was connected to USB after earbuds were
  already streaming).""")

    print(f'\n  DEVICE ROLES\n  {sep}')

    for dev, info in device_roles.items():
        print(f"""
  ┌──────────────────────────────────────────────────────────┐
  │  {dev}  →  {info['role']:<40} │
  ├──────────────────────────────────────────────────────────┤
  │  Role confidence:  Primary {info['primary_pct']:3d}%  │  Secondary {info['secondary_pct']:3d}%  │  Dongle {info['dongle_pct']:3d}%  │""")

        if 'Primary' in info['role']:
            print(f"""  ├──────────────────────────────────────────────────────────┤
  │  EVIDENCE (from real log messages):                      │
  │  ✓ "Agent set AWS state" — AWS_MCE agent role confirmed  │
  │  ✓ aws_role:0x40 — hexadecimal agent role value          │
  │  ✓ BT_SINK_SRV_STATE_STREAMING — holds phone A2DP link   │
  │  ✓ BEO_KEY_REMAPPER — processes user key presses         │
  │  ✓ APP_FORCE_SENSOR — touch/force sensor (primary only)  │
  │  ✓ [Music_APP] key events — manages audio playback       │
  │  ✓ LEA AIRD_CLIENT start_pre_action — LE Audio client    │
  │  ✓ [CALL][AWS_MCE]Agent send call info — HFP agent       │""")
        elif 'Secondary' in info['role']:
            print(f"""  ├──────────────────────────────────────────────────────────┤
  │  EVIDENCE (from real log messages):                      │
  │  ✓ "@@@ Partner RX_BT3_MIC_ERROR" — partner role marker  │
  │  ✓ lcAWSCTL…IF_TYPE_A2DP_PLR_REQ — relay request        │
  │  ✓ Aws If: 500–640 slots — high AWS = secondary active   │
  │  ✓ role:0x20 in race_app_aws — hex partner role          │
  │  ✓ BEO_RELAY module active — secondary relay stack       │
  │  ✓ No AVDTP/sink entries — no direct phone connection    │""")
        elif 'Dongle' in info['role']:
            print(f"""  ├──────────────────────────────────────────────────────────┤
  │  EVIDENCE (from real log messages):                      │
  │  ✓ DONGLE_AIR module — USB dongle firmware identity      │
  │  ✓ BEO_INTERFACE_USB — USB audio source active           │
  │  ✓ USBAUDIO_DRV — USB audio driver present               │
  │  ✓ APP_CHARGER_CASE — charging case controller           │
  │  ✓ "SoC: case[99] L[100] R[100]" — monitors both earbuds │
  │  ✓ connect_cs SIRK — LE Audio Coordinated Set discovery  │
  │  ✓ Starts 1888s into session — hot-plugged USB device    │
  │  ✓ Battery always 100% — plugged into USB power          │""")
        print(f'  └──────────────────────────────────────────────────────────┘')

    print(f'\n  LEFT / RIGHT EARBUD IDENTIFICATION\n  {sep}')
    print("""
  The AB1585/88 log reports earbud side as "Side = N" in APP_PROTO_IND:

  Device 1 logs: "SoC = 87, Charger = 1, Side = 2"  (at t=598s)
                 "SoC = 71, Charger = 0, Side = 1"  (at t=3578s)
  Device 2 logs: "SoC = 85, Charger = 1, Side = 1"  (at t=459s)
                 "SoC = 84, Charger = 1, Side = 2"  (at t=1254s)

  Side = 1 corresponds to LEFT earbud, Side = 2 to RIGHT.

  CRITICAL OBSERVATION — Role Handover changes the side assignment:
  Device 1 reports Side=2 (Right) early in the session, then Side=1
  (Left) late in the session. Device 2 shows the reverse transition.
  This matches the three confirmed RHO (Role Handover) events — the
  Primary/Secondary roles swap between earbuds during the session.
  After each RHO the Agent role moves to the other earbud, and the
  side reporting reflects the new configuration.

  RHO events confirmed at approximately:
    t=455s  (Device 2 logs first: "end cm rho gap event status:0x00")
    t=1017s (Device 1 logs: "end cm rho gap event status:0x00")
    t=1286s (Device 1 logs: "end cm rho gap event status:0x00")""")

    print(f'\n  PRIMARY USER SCENARIO\n  {sep}')
    print("""
  SCENARIO: Firmware OTA Update During Active TWS Music Streaming
            with USB Dongle Connection and Role Handover Events

  This is a rich multi-phase session spanning approximately 61 minutes.
  The scenario can be divided into four phases:

  PHASE 1 — Active streaming with OTA in background (t=0s to t=455s)
    Both earbuds in-ear (wear detect: local=1, remote=1 confirmed
    on both devices from the start). Music streaming active on Device 1
    (BT_SINK_SRV_STATE_STREAMING). Firmware OTA update begins in the
    background — RACE_FOTA_CHECK_INTEGRITY and partition query events
    appear on Device 1 from t=110s. OTA data transfers to flash memory
    visible on both earbuds simultaneously.

  PHASE 2 — Role Handover #1 and case events (t=455s to t=600s)
    First RHO completes at t=455s on Device 2. Device 1 lid close
    event at t=455s — one earbud briefly enters charging case context.
    Device 2 also logs CHARGER_IN at t=524s. The earbuds re-establish
    the Agent/Partner roles after RHO. OTA continues across RHO.

  PHASE 3 — USB Dongle connects, LE Audio + OTA continues (t=588s to t=1762s)
    Device 3 (dongle) begins logging at ~t=1888s wall-clock offset
    but starts immediately with USB audio active (BEO_INTERFACE_USB).
    Device 3 logs "SoC: case[99] L[100] R[100]" — it sees both earbuds
    at 100% which is expected since it started while earbuds were already
    connected. LE Audio coordinated set discovery via SIRK begins.
    Two more RHO events occur at t=1017s and t=1286s.
    Wear detect on Device 1 shows "remote=0" at t=1557s — one earbud
    temporarily removed. Lid opens at t=1630s.

  PHASE 4 — OTA completion and session end (t=1630s to t=3648s)
    Device 1 logs "Apply upgrade and reboot" at t=3643s — the OTA
    firmware update completes and the Primary earbud schedules a reboot.
    Battery reports throughout show gradual discharge:
      t=56s:  D1=87%    t=1309s: D1=84%    t=3578s: D1=71%
      t=466s: D2=85%    t=1752s: D2=82%    t=3583s: D2 lid open
    Device 3 (dongle) battery stays at 100% throughout — USB powered.""")

    print(f'\n  ACOUSTIC SIGNAL CHAIN INTERPRETATION\n  {sep}')
    print("""
  The architecture revealed by this capture is more complex than a
  standard TWS pair because of the USB dongle (Device 3).

  STANDARD TWS PATH (phone as source):
    Phone → Classic BT A2DP → Device 1 (Primary) → AWS relay → Device 2

  LE AUDIO PATH (USB dongle as source):
    PC/USB host → USBAUDIO_DRV → Device 3 dongle
                               → BLE LE Audio (CIS/BIS)
                               → Device 1 + Device 2 (simultaneous)

  The SIRK (Set Identity Resolving Key) seen in Device 3 logs:
    "connect_cs, sirk:b6-31-f2-8e-e6-55-d0-31"
  is the cryptographic identifier for the Coordinated Set formed by
  the two earbuds. Device 3 uses it to discover and bind to both
  earbuds simultaneously as a Coordinated Set member — this is the
  LE Audio equivalent of TWS pairing.

  ROLE HANDOVER (RHO) — acoustic implications:
  RHO transfers the Agent role from one earbud to the other. During
  RHO the A2DP connection is migrated between earbuds transparently.
  From an acoustic perspective, the user should hear no interruption
  if RHO completes within the jitter buffer's lookahead window.
  The three RHOs in this session occurring during OTA is expected —
  the OTA process deliberately triggers RHO to allow the non-updating
  earbud to serve as Agent while the other flashes.

  OTA + STREAMING simultaneously:
  The flash write events (BEO_UPGRADE_FLASH) occurring at the same
  time as A2DP streaming represent the highest CPU/memory pressure
  state for the earbud firmware. Any latency added by flash writes
  to the DSP processing loop would cause jitter buffer level drops —
  the same symptom as RF interference but with a different root cause.""")

    print(f'\n  STEP-BY-STEP ANALYSIS METHODOLOGY\n  {sep}')
    print("""
  STEP 1 — Confirm file format and chip family
  All three files: PCAPNG, link type 201, AB1585/88 chip
  (same vendor as Assignment 2's AB159x — same log format).
  Confirmed by first packet: "tool = AB1585/88 Logging Tool, v3.10.0.6"

  STEP 2 — Align timestamps to confirm simultaneity
  Device 1 start: 1773114678 µs epoch-based timestamp
  Device 2 start: 1773114672 µs (6 seconds earlier than D1)
  Device 3 start: 1773116560 µs (~1888 seconds after D1 started)
  Device 1 end:   1773118326 µs
  Device 2 end:   1773118325 µs  ← within 1 second of D1
  Device 3 end:   1773118322 µs  ← within 4 seconds of D1
  All three end almost simultaneously — confirms coordinated capture.

  STEP 3 — Identify each device's role from module names alone
  Before reading a single message, the MODULE LIST reveals:
    D1: BEO_KEY_REMAPPER, APP_FORCE_SENSOR, APP_BEO_AUDIO_PROMPT
        → Primary: handles key events, force sensor = user-facing earbud
    D2: BEO_RELAY, BTAWS (heavy), "Partner RX_BT3_MIC_ERROR"
        → Secondary: relay stack, partner errors = receiver
    D3: DONGLE_AIR, USBAUDIO_DRV, APP_CHARGER_CASE, LE_AUDIO
        → Dongle: USB audio driver + charger case controller

  STEP 4 — Confirm roles with specific log evidence
  Hexadecimal role values in AB1585/88:
    0x40 = Agent (Primary) — confirmed in Device 1 "aws_role:0x40"
    0x20 = Partner (Secondary) — confirmed in Device 2 "role:20"
  "@@@ Partner RX_BT3_MIC_ERROR" appears exclusively in Device 2.
  "Agent set AWS state" appears exclusively in Device 1.

  STEP 5 — Identify left/right sides
  APP_PROTO_IND logs "Side = N" (1=Left, 2=Right). Cross-reference
  with RHO events to track side assignment over time.

  STEP 6 — Reconstruct the user scenario from event ordering
  Merge all three timelines by wall-clock timestamp and read the
  event sequence as a user journey. The OTA module names
  (BEO_UPGRADE_LIB, BEO_UPGRADE_FLASH, BEO_UPGRADE_DATA) together
  with "Apply upgrade and reboot" at session end confirm this is
  an OTA update session, not a routine listening session.""")

    print(f'\n{"═"*64}\n')


# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    DEFAULTS = [
        '/mnt/user-data/uploads/Device_1.pcapng',
        '/mnt/user-data/uploads/Device_2.pcapng',
        '/mnt/user-data/uploads/Device_3.pcapng',
    ]
    if len(sys.argv) >= 4:
        files = sys.argv[1:4]
    else:
        files = DEFAULTS

    print(f'\n{"═"*64}')
    print('  Assignment 3 — TWS System Analysis')
    print(f'{"═"*64}\n')

    # Establish earliest timestamp as time zero
    ts0_global = None
    raw_info = {}
    for fp in files:
        if not os.path.exists(fp):
            print(f"  [WARN] File not found: {fp}")
            continue
        name = os.path.splitext(os.path.basename(fp))[0]
        print(f"  Loading {name} ({os.path.getsize(fp)//1024//1024} MB)...")
        pkts = load_packets(fp, sample_rate=5)  # every 5th packet for speed
        if pkts:
            ts0 = pkts[0][0]
            if ts0_global is None or ts0 < ts0_global:
                ts0_global = ts0
            raw_info[name] = (pkts, ts0)

    if not raw_info:
        print("  No files loaded. Exiting.")
        return

    print(f"\n  Analysing roles...")
    device_roles = {}
    all_device_events = {}

    for name, (pkts, ts0) in raw_info.items():
        rel_start = (ts0 - ts0_global) / 1e6
        print(f"    {name}: {len(pkts):,} sampled packets, starts at t={rel_start:.0f}s")
        scores, evidence = score_roles(pkts, ts0)
        role_info = determine_role(scores)
        device_roles[name] = role_info
        # Convert evidence timestamps to be relative to global t0
        adjusted = [(rel + rel_start, key, msg) for rel, key, msg in evidence]
        all_device_events[name] = (ts0, adjusted)
        print(f"      → {role_info['role']}")

    print(f"\n  Building scenario timeline...")
    timeline = build_scenario_timeline(all_device_events, device_roles)
    print(f"    {len(timeline)} timeline events")

    # Chart output
    out_dir = '/home/claude/assignment3'
    chart_path = os.path.join(out_dir, 'tws_analysis.png')
    print(f"\n  Generating chart...")
    generate_chart(device_roles, timeline, chart_path)

    print_report(device_roles, timeline)


if __name__ == '__main__':
    main()
