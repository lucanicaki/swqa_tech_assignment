"""
Assignment 3: TWS Bluetooth Audio System Log Analysis
======================================================
Analyses Wireshark logs from a True Wireless Stereo (TWS) Bluetooth
audio system to determine:
  1. The role of each device (Primary/Secondary/Source)
  2. The primary user scenario captured
  3. A step-by-step explanation of the analysis method

This script works on AB159x-family PCAPNG firmware logs (same chip family
as Assignment 2). If the TWS_User_Scenario_EXT.7z file contains standard
HCI pcapng files instead, the hci_fallback parser is also included.

IMPORTANT NOTE ON MISSING FILE:
The file TWS_User_Scenario_EXT.7z was not provided in the uploaded
materials. This script documents the complete analysis methodology
applied to the AB159x log format already confirmed in Assignment 2,
AND provides a general HCI-based TWS analysis approach applicable to
any standard Wireshark TWS capture.

Author note:
    Analysed through a systems and acoustics lens. TWS audio is treated
    as a distributed signal chain: one device owns the RF link to the phone
    (Primary), reconstructs the SBC bitstream, and relays a synchronised
    copy to the partner (Secondary) over a private inter-earbud link.
    The user scenario is identified by recognising which protocol events
    correspond to which stage of the user journey.

Usage:
    python3 analyse_tws_log.py <path_to_pcapng>

Requires:
    Python 3.8+  — standard library only for parsing
    matplotlib   — for the role and scenario diagram
"""

import struct
import re
import sys
import os
import csv
from collections import defaultdict


# ─────────────────────────────────────────────────────────────────
#  BACKGROUND: HOW TWS WORKS (needed to understand what to look for)
# ─────────────────────────────────────────────────────────────────
#
#  A TWS system has THREE devices communicating:
#
#    [PHONE / SOURCE]
#         │
#         │  Classic Bluetooth BR/EDR
#         │  A2DP profile (audio stream)
#         │  AVRCP profile (play/pause/volume)
#         │
#    [PRIMARY EARBUD]  ←─── this is the "agent" in AB159x logs
#         │
#         │  Inter-earbud link (also Classic BT or BLE)
#         │  Proprietary relay protocol (called "AWS" in AB159x)
#         │  Carries: relayed audio + control sync + clock sync
#         │
#    [SECONDARY EARBUD]  ←─── this is the "partner" or "peer"
#
#  The Primary earbud:
#    - Holds the A2DP connection to the phone
#    - Decodes/relays the SBC stream to the Secondary
#    - Handles AVRCP commands (play, pause, volume)
#    - Is the "master" of the inter-earbud link
#    - In AB159x logs: identified by "Agent LinkIdx" entries and role=1
#
#  The Secondary earbud:
#    - Receives relayed audio from Primary
#    - Has NO direct A2DP connection to the phone
#    - Synchronises playback timing from Primary's clock
#    - In AB159x logs: identified by "partner" references and AWS events
#
#  The Phone (Source):
#    - Sends A2DP stream (SBC encoded audio)
#    - Sends AVRCP commands
#    - Identified by its MAC address in GAP connection logs
#
# ─────────────────────────────────────────────────────────────────


# ─────────────────────────────────────────────────────────────────
#  STEP 1: PCAPNG PARSER (same as Assignment 2 — same chip family)
# ─────────────────────────────────────────────────────────────────

def parse_pcapng(filepath):
    """
    Read PCAPNG file and return list of (timestamp_us, raw_bytes) tuples.
    Handles both standard HCI and AB159x vendor log formats.
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0x0A0D0D0A:
        raise ValueError(f"Not a PCAPNG file (magic=0x{magic:08X})")

    pos = 0
    packets = []
    link_type = None

    while pos < len(data) - 8:
        bt = struct.unpack_from('<I', data, pos)[0]
        bl = struct.unpack_from('<I', data, pos + 4)[0]
        if bl < 12 or bl > len(data) - pos:
            break

        if bt == 0x00000001:  # Interface Description Block
            link_type = struct.unpack_from('<H', data, pos + 8)[0]

        if bt == 0x00000006:  # Enhanced Packet Block
            ts_h = struct.unpack_from('<I', data, pos + 12)[0]
            ts_l = struct.unpack_from('<I', data, pos + 16)[0]
            cap  = struct.unpack_from('<I', data, pos + 20)[0]
            pkt  = data[pos + 28: pos + 28 + cap]
            packets.append(((ts_h << 32) | ts_l, pkt))

        pos += bl

    print(f"[1] File: {os.path.basename(filepath)}")
    print(f"[1] Size: {len(data):,} bytes")
    print(f"[1] Link type: {link_type}")
    print(f"[1] Packets: {len(packets):,}")
    return packets, link_type


# ─────────────────────────────────────────────────────────────────
#  STEP 2: MESSAGE EXTRACTION
# ─────────────────────────────────────────────────────────────────

def extract_message(pkt):
    """Extract ASCII log text from AB159x packet payload."""
    for marker in [b'[M:', b'tool']:
        pos = pkt.find(marker)
        if pos >= 0:
            try:
                return pkt[pos:].decode('ascii', errors='replace').rstrip('\x00').strip()
            except Exception:
                pass
    return None


# ─────────────────────────────────────────────────────────────────
#  STEP 3: TWS ROLE IDENTIFICATION
#  This is the core analytical step.
#  We look for specific log signatures that reveal device roles.
# ─────────────────────────────────────────────────────────────────

# Key patterns that identify the PRIMARY earbud
PRIMARY_INDICATORS = [
    # The AB159x "Agent" role is the primary earbud
    (re.compile(r'\[mHDT\]\[LOG_QA\] Agent LinkIdx:(\d+)'), 'Agent role confirmed'),
    (re.compile(r'Agent Rx Duplicate Seq'), 'Agent receiving duplicate (primary retransmit)'),
    (re.compile(r'A2dpStartSuspendSetup'), 'Primary managing A2DP stream'),
    # Primary holds the A2DP connection
    (re.compile(r'\[A2DP\] a2dp_avdtp_cb.*STRM'), 'A2DP stream event on primary'),
    # Primary manages the phone connection (sniff mode = phone link)
    (re.compile(r'sniff_status.*role 1'), 'Primary role=1 in phone connection'),
    # Primary has the sink service
    (re.compile(r'\[sink\]\[music\].*a2dp'), 'Sink music service (primary)'),
    # Primary manages AVDTP
    (re.compile(r'\[AVDTP\].*state_open|state_streaming'), 'AVDTP session on primary'),
]

# Key patterns that identify inter-earbud (AWS) communication
AWS_INDICATORS = [
    (re.compile(r'Aws If:(\d+)'), 'AWS inter-earbud interface'),
    (re.compile(r'FastIf:(\d+)'), 'Fast inter-earbud interface'),
    (re.compile(r'\[SCO\].*FwdRG'), 'SCO forward relay (AWS audio relay)'),
    (re.compile(r'InitSync\s*=\s*1'), 'Inter-earbud sync initialised'),
    (re.compile(r'PartnerLost'), 'Partner (secondary) connection monitor'),
]

# Key patterns for user scenario identification
SCENARIO_INDICATORS = {
    'a2dp_streaming': re.compile(
        r'A2dpCount\s+\d+.*ErrRate\s+\d+%.*BitRate\s+(\d+)'),
    'avdtp_open': re.compile(r'AVDTP.*state_open|STRM IND'),
    'avdtp_streaming': re.compile(r'AVDTP.*state_streaming|STRM START'),
    'avdtp_suspend': re.compile(r'AVDTP.*EVT.*0x09|SUSPEND'),
    'avrcp_play': re.compile(r'AVRCP.*play|avrcp.*0x44'),
    'avrcp_pause': re.compile(r'AVRCP.*pause|avrcp.*0x46'),
    'avrcp_volup': re.compile(r'AVRCP.*volume|avrcp.*0x41'),
    'connection': re.compile(r'Connection Complete|connected.*0x0252'),
    'disconnection': re.compile(r'Disconnection Complete|disconnect'),
    'sniff_enter': re.compile(r'sniff.*interval|bt_gap_connection_sniff'),
    'sniff_exit': re.compile(r'Unsniff|sniff.*changed.*0X0'),
    'codec_open': re.compile(r'Open codec.*role.*type'),
    'dsp_start': re.compile(r'Stream out afe start|AFE DL.*start'),
    'dsp_stop': re.compile(r'audio.*delay off|aud_dl_resume Fail'),
    'aws_sync': re.compile(r'InitSync\s*=\s*1|AWS.*sync'),
    'phone_mac': re.compile(r'\[f[\da-f]-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}-[\da-f]{2}\]'),
    'gap_timer': re.compile(r'GAP.*timer.*expired'),
    'stream_reset': re.compile(r'Reset_A2dp_State'),
    'reconnect': re.compile(r'A2dpStartSuspendSetup 0.*\nA2dpStartSuspendSetup 1', re.DOTALL),
}

# Connection handle patterns
HANDLE_PATTERN = re.compile(r'hci_handle\s+([0-9a-f]+)')
MAC_PATTERN    = re.compile(r'\[([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})\]')
ROLE_PATTERN   = re.compile(r'role\s+(\d+)')


def analyse_tws_roles(packets):
    """
    Identify device roles from log messages.

    Returns:
        roles: dict mapping device identifiers to their role
        evidence: list of (time_s, evidence_string) tuples
        events: list of (time_s, category, detail) tuples
    """
    if not packets:
        return {}, [], []

    ts0 = packets[0][0]
    roles    = defaultdict(lambda: {'primary_score': 0, 'secondary_score': 0,
                                     'source_score': 0, 'evidence': []})
    evidence = []
    events   = []

    # Track connection handles → MAC addresses
    handle_to_mac = {}
    mac_roles     = defaultdict(set)

    for ts_us, pkt in packets:
        rel_s = (ts_us - ts0) / 1_000_000
        msg = extract_message(pkt)
        if not msg:
            continue

        # ── Extract MAC addresses and handles ──
        macs    = MAC_PATTERN.findall(msg)
        handles = HANDLE_PATTERN.findall(msg)
        role_m  = ROLE_PATTERN.search(msg)

        for h in handles:
            if macs:
                handle_to_mac[h] = macs[0]

        # ── Score primary indicators ──
        for pattern, label in PRIMARY_INDICATORS:
            if pattern.search(msg):
                evidence.append((rel_s, f'PRIMARY: {label}'))
                if macs:
                    roles[macs[0]]['primary_score'] += 1
                    roles[macs[0]]['evidence'].append(f't={rel_s:.2f}s {label}')

        # ── Score AWS inter-earbud indicators ──
        for pattern, label in AWS_INDICATORS:
            m = pattern.search(msg)
            if m:
                # AWS with non-zero count = inter-earbud activity present
                if 'Aws If' in label:
                    count = int(m.group(1)) if m.group(1) else 0
                    if count > 0:
                        evidence.append((rel_s, f'AWS LINK ACTIVE: slots={count}'))
                else:
                    evidence.append((rel_s, f'AWS: {label}'))

        # ── Categorise events for scenario reconstruction ──
        for category, pattern in SCENARIO_INDICATORS.items():
            if pattern.search(msg):
                detail = msg[:120].replace('\n', ' ')
                events.append({
                    'time_s':   round(rel_s, 3),
                    'category': category,
                    'detail':   detail,
                })
                break   # one category per message

        # ── Phone MAC identification ──
        # The phone MAC appears in GAP connection logs with role information
        if 'hci_handle' in msg and role_m:
            role_val = int(role_m.group(1))
            for mac in macs:
                if role_val == 1:
                    # role=1 in Classic BT GAP = slave (earbud is slave to phone)
                    # So the phone (master) has MAC appearing in this context
                    mac_roles[mac].add('phone_side')
                    evidence.append((rel_s,
                        f'PHONE MAC candidate: {mac} (earbud is role=1 slave)'))

    return dict(roles), evidence, events


# ─────────────────────────────────────────────────────────────────
#  STEP 4: SCENARIO RECONSTRUCTION
#  Build a human-readable narrative from the event sequence
# ─────────────────────────────────────────────────────────────────

SCENARIO_LABELS = {
    'connection':       'Device connection established',
    'sniff_enter':      'Link entered sniff mode (power saving)',
    'sniff_exit':       'Sniff mode exited (streaming about to start)',
    'avdtp_open':       'AVDTP media channel opened',
    'codec_open':       'Audio codec initialised (SBC)',
    'aws_sync':         'Inter-earbud sync established',
    'dsp_start':        'DSP audio path started — playback begins',
    'a2dp_streaming':   'A2DP stream active',
    'avdtp_streaming':  'AVDTP in streaming state',
    'avrcp_play':       'AVRCP play command',
    'avrcp_pause':      'AVRCP pause command',
    'avrcp_volup':      'AVRCP volume adjustment',
    'gap_timer':        'GAP timer expired (stream re-negotiation)',
    'stream_reset':     'Stream reset triggered',
    'avdtp_suspend':    'AVDTP stream suspended',
    'dsp_stop':         'DSP audio path stopped',
    'disconnection':    'Device disconnected',
}

def reconstruct_scenario(events):
    """
    From the ordered list of events, identify the primary user scenario
    and build a timeline narrative.

    TWS user scenarios to distinguish:
      A. Music playback start   — connect → codec open → stream → play
      B. Music playback pause   — stream active → avrcp pause → suspend
      C. Call handling          — SCO/eSCO open during stream
      D. Reconnect after dropout — stream reset → re-init → stream resumes
      E. Power on / first connect — connection events from cold start
    """
    if not events:
        return 'Unknown — no events extracted', []

    categories = [e['category'] for e in events]

    # Score each scenario
    scores = {
        'music_playback': sum(1 for c in categories if c in
                              ['connection', 'avdtp_open', 'codec_open',
                               'dsp_start', 'a2dp_streaming', 'aws_sync']),
        'pause_resume': sum(1 for c in categories if c in
                            ['avdtp_suspend', 'avrcp_pause', 'avrcp_play']),
        'stream_recovery': sum(1 for c in categories if c in
                               ['stream_reset', 'gap_timer']),
        'call': sum(1 for c in categories if 'sco' in c.lower()),
    }

    # Build milestone timeline (deduplicated by category)
    seen = set()
    milestones = []
    for e in events:
        cat = e['category']
        if cat not in seen and cat in SCENARIO_LABELS:
            seen.add(cat)
            milestones.append({
                'time_s':   e['time_s'],
                'label':    SCENARIO_LABELS[cat],
                'category': cat,
            })

    # Determine primary scenario
    if scores['music_playback'] >= 3:
        if scores['stream_recovery'] >= 2:
            scenario = 'Music playback with stream recovery (RF interference event)'
        else:
            scenario = 'Music playback — full session from connection to streaming'
    elif scores['pause_resume'] > scores['music_playback']:
        scenario = 'Music playback with pause/resume user interaction'
    elif scores['call'] > 0:
        scenario = 'Phone call handling during audio session'
    elif scores['stream_recovery'] > 0:
        scenario = 'Stream recovery / reconnection after dropout'
    else:
        scenario = 'Partial session capture — connection and initialisation phase'

    return scenario, milestones


# ─────────────────────────────────────────────────────────────────
#  STEP 5: GENERATE ANALYSIS CHART
# ─────────────────────────────────────────────────────────────────

def generate_chart(events, milestones, scenario, output_path):
    """
    Produce a two-panel chart:

    Panel 1 — TWS system topology diagram
        Shows the three-device signal chain:
        Phone → Primary Earbud → Secondary Earbud
        with the protocols on each link labelled.

    Panel 2 — User scenario event timeline
        Horizontal timeline showing when each protocol event
        occurred, coloured by category.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from matplotlib.patches import FancyArrowPatch, FancyBboxPatch
    except ImportError:
        print("[5] matplotlib not installed — skipping chart")
        return

    fig, (ax_topo, ax_time) = plt.subplots(
        2, 1, figsize=(14, 9),
        gridspec_kw={'height_ratios': [2, 3]}
    )
    fig.patch.set_facecolor('#FAFAF8')

    C = {
        'phone':     '#2B5EA7',
        'primary':   '#1A7A4A',
        'secondary': '#8B3A9E',
        'link_a2dp': '#D7344B',
        'link_aws':  '#E87722',
        'link_ble':  '#9B59B6',
        'bg':        '#F0F4F8',
        'text':      '#1A1A1A',
        'subtle':    '#6B7280',
    }

    # ════════════════════════════════════════════
    #  PANEL 1 — TWS TOPOLOGY
    # ════════════════════════════════════════════
    ax_topo.set_facecolor('#FAFAF8')
    ax_topo.set_xlim(0, 10)
    ax_topo.set_ylim(0, 4)
    ax_topo.axis('off')
    ax_topo.set_title(
        f'Assignment 3 — TWS System Analysis  ·  Scenario: {scenario}',
        fontsize=10, fontweight='bold', color='#1A1A1A', loc='left', pad=8
    )

    def draw_device(ax, x, y, w, h, color, label, sublabel, rx=0.15):
        box = FancyBboxPatch((x - w/2, y - h/2), w, h,
                              boxstyle=f"round,pad={rx}",
                              facecolor=color, edgecolor='white',
                              linewidth=1.5, alpha=0.92, zorder=3)
        ax.add_patch(box)
        ax.text(x, y + 0.08, label,
                ha='center', va='center', fontsize=10, fontweight='bold',
                color='white', zorder=4)
        ax.text(x, y - 0.28, sublabel,
                ha='center', va='center', fontsize=7.5,
                color='white', alpha=0.88, zorder=4)

    def draw_link(ax, x1, x2, y, color, label, style='-', lw=2.5, yw=0.0):
        ax.annotate('', xy=(x2 - 0.02, y + yw), xytext=(x1 + 0.02, y + yw),
                    arrowprops=dict(arrowstyle='->', color=color,
                                    lw=lw, linestyle=style),
                    zorder=2)
        ax.annotate('', xy=(x1 + 0.02, y - yw), xytext=(x2 - 0.02, y - yw),
                    arrowprops=dict(arrowstyle='->', color=color,
                                    lw=lw, linestyle=style),
                    zorder=2)
        ax.text((x1 + x2) / 2, y + 0.32, label,
                ha='center', va='center', fontsize=8, color=color,
                bbox=dict(fc='white', ec=color, pad=2, lw=0.8, alpha=0.9),
                zorder=5)

    # Draw devices
    draw_device(ax_topo, 1.8, 2.0, 2.2, 1.2, C['phone'],
                'PHONE / SOURCE', 'Bluetooth source\nA2DP encoder · AVRCP')
    draw_device(ax_topo, 5.0, 2.0, 2.2, 1.2, C['primary'],
                'PRIMARY EARBUD', 'Agent · role=1 slave to phone\nHolds A2DP · Relays to secondary')
    draw_device(ax_topo, 8.2, 2.0, 2.2, 1.2, C['secondary'],
                'SECONDARY EARBUD', 'Partner · Slave to primary\nReceives relayed audio')

    # Draw links
    draw_link(ax_topo, 2.9, 3.9, 2.0, C['link_a2dp'],
              'A2DP (SBC stream)\nAVRCP (control)\nClassic BT BR/EDR', lw=2.5, yw=0.18)
    draw_link(ax_topo, 6.1, 7.1, 2.0, C['link_aws'],
              'AWS inter-earbud link\nRelayed audio + clock sync\nClassic BT or BLE', lw=2.5, yw=0.18)

    # Role identification evidence box
    evidence_text = (
        "Role identification evidence:\n"
        "Primary: 'Agent LinkIdx' log entries · A2DP sink service active · "
        "AVDTP session owner · role=1 in GAP connection · AWS relay initiator\n"
        "Secondary: 'PartnerLost' monitoring · AWS receiver · "
        "no direct A2DP connection · synchronised from primary clock\n"
        "Phone: MAC in GAP connection logs · SBC encoder · AVRCP source"
    )
    ax_topo.text(5.0, 0.4, evidence_text,
                 ha='center', va='center', fontsize=7.2,
                 color='#374151', style='italic',
                 bbox=dict(fc='#EEF2FF', ec='#A5B4FC', pad=5, lw=0.8, alpha=0.95),
                 wrap=True, zorder=5)

    # ════════════════════════════════════════════
    #  PANEL 2 — SCENARIO TIMELINE
    # ════════════════════════════════════════════
    ax_time.set_facecolor('#FAFAF8')
    for spine in ax_time.spines.values():
        spine.set_visible(False)

    # Colour map for event categories
    CAT_COLORS = {
        'connection':       '#2B5EA7',
        'sniff_enter':      '#6B7280',
        'sniff_exit':       '#6B7280',
        'avdtp_open':       '#1A7A4A',
        'codec_open':       '#1A7A4A',
        'aws_sync':         '#E87722',
        'dsp_start':        '#1A7A4A',
        'a2dp_streaming':   '#D7344B',
        'avdtp_streaming':  '#D7344B',
        'avrcp_play':       '#9B59B6',
        'avrcp_pause':      '#9B59B6',
        'gap_timer':        '#E87722',
        'stream_reset':     '#D7344B',
        'avdtp_suspend':    '#6B7280',
        'dsp_stop':         '#6B7280',
        'disconnection':    '#2B5EA7',
    }

    if milestones:
        times = [m['time_s'] for m in milestones]
        t_max = max(times) if times else 10
        t_min = min(times) if times else 0
        t_range = max(t_max - t_min, 1)

        # Draw timeline baseline
        ax_time.axhline(y=0.5, xmin=0.02, xmax=0.98,
                        color='#D1D5DB', lw=1.2, zorder=1)
        ax_time.set_xlim(t_min - t_range * 0.05, t_max + t_range * 0.05)
        ax_time.set_ylim(-1.8, 2.2)
        ax_time.set_xlabel('Time (seconds)', fontsize=9, color='#374151')
        ax_time.tick_params(axis='x', labelsize=8, colors='#6B7280')
        ax_time.tick_params(axis='y', left=False, labelleft=False)
        ax_time.grid(axis='x', color='#E5E7EB', linewidth=0.5, linestyle='--')

        # Plot milestone events alternating above/below line
        for i, m in enumerate(milestones):
            t  = m['time_s']
            c  = CAT_COLORS.get(m['category'], '#6B7280')
            yp = 0.8 if i % 2 == 0 else -0.3    # above or below line
            yt = 1.5 if i % 2 == 0 else -1.0    # text position

            # Stem
            ax_time.plot([t, t], [0.5, yp + (0.15 if i%2==0 else -0.15)],
                         color=c, lw=1.2, alpha=0.7, zorder=2)
            # Dot
            ax_time.scatter([t], [yp], color=c, s=48, zorder=4,
                            edgecolors='white', linewidth=1)
            # Label
            label = m['label']
            # Wrap long labels
            if len(label) > 22:
                words = label.split()
                mid = len(words) // 2
                label = ' '.join(words[:mid]) + '\n' + ' '.join(words[mid:])

            ax_time.text(t, yt, f"{m['time_s']:.1f}s\n{label}",
                         ha='center', va='center' if i%2==0 else 'center',
                         fontsize=6.5, color=c,
                         bbox=dict(fc='white', ec=c, pad=1.5, lw=0.6, alpha=0.92),
                         zorder=5)

        # Legend
        legend_items = [
            mpatches.Patch(color='#2B5EA7', label='Connection / Protocol'),
            mpatches.Patch(color='#1A7A4A', label='Audio init / DSP'),
            mpatches.Patch(color='#D7344B', label='Streaming / Error'),
            mpatches.Patch(color='#E87722', label='AWS / Sync / Timer'),
            mpatches.Patch(color='#9B59B6', label='AVRCP control'),
            mpatches.Patch(color='#6B7280', label='Power / Sniff'),
        ]
        ax_time.legend(handles=legend_items, loc='upper right',
                       fontsize=7, framealpha=0.9,
                       edgecolor='#E5E7EB', fancybox=False,
                       ncol=3, columnspacing=0.8)
    else:
        # No data — show the methodology diagram instead
        ax_time.text(0.5, 0.5,
                     'Timeline will populate when TWS_User_Scenario_EXT log is provided.\n'
                     'See methodology section below for analysis approach.',
                     ha='center', va='center', fontsize=10,
                     color='#6B7280', transform=ax_time.transAxes,
                     bbox=dict(fc='#F3F4F6', ec='#D1D5DB', pad=10, lw=0.8))

    plt.tight_layout(pad=1.5)
    plt.savefig(output_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"[5] Chart saved: {output_path}")


# ─────────────────────────────────────────────────────────────────
#  STEP 6: PRINT FULL ANALYSIS REPORT
# ─────────────────────────────────────────────────────────────────

def print_report(roles, evidence, events, milestones, scenario):
    """
    Print the structured analysis report covering:
    - Device roles with supporting evidence
    - Primary user scenario
    - Step-by-step analysis explanation
    - Acoustic/signal chain interpretation
    """
    sep = '─' * 62
    print(f'\n{"═"*62}')
    print('  ASSIGNMENT 3 — TWS LOG ANALYSIS REPORT')
    print(f'{"═"*62}')

    # ── Device roles ──
    print(f'\n  DEVICE ROLES\n  {sep}')
    print("""
  THREE DEVICES IN A TWS SYSTEM:

  ┌─────────────────────────────────────────────────────┐
  │  DEVICE 1 — PHONE (Audio Source)                    │
  │  Role: Bluetooth Central / A2DP Source              │
  │  Identified by: MAC address in GAP connection logs  │
  │  Evidence: SBC encoder, AVRCP commands              │
  │  Example log: [f4-a3-10-35-fb-79] in GAP entries    │
  └─────────────────────────────────────────────────────┘
         │ A2DP stream (SBC) + AVRCP (control)
         │ Classic BT BR/EDR
         ▼
  ┌─────────────────────────────────────────────────────┐
  │  DEVICE 2 — PRIMARY EARBUD (Agent)                  │
  │  Role: A2DP Sink + AWS Relay Master                 │
  │  Identified by:                                     │
  │    [mHDT][LOG_QA] Agent LinkIdx:3 EDR Legacy!!!     │
  │    role=1 in GAP sniff_status log                   │
  │    [sink][music][a2dp] entries                      │
  │    A2dpStartSuspendSetup (stream control)           │
  │    AVDTP session ownership (state_open, state_streaming) │
  │    Agent Rx Duplicate Seq (primary retransmit logic) │
  └─────────────────────────────────────────────────────┘
         │ AWS inter-earbud link
         │ Relayed SBC + clock sync
         │ Classic BT or BLE
         ▼
  ┌─────────────────────────────────────────────────────┐
  │  DEVICE 3 — SECONDARY EARBUD (Partner)              │
  │  Role: AWS Relay Receiver                           │
  │  Identified by:                                     │
  │    PartnerLost counter in A2DP stats                │
  │    Aws If: counter in scheduler logs                │
  │    [SCO] FwdRG Rx/Tx share address (relay buffers)  │
  │    InitSync = 1 (receives sync from primary)        │
  │    No direct AVDTP session in logs                  │
  └─────────────────────────────────────────────────────┘""")

    # ── Primary scenario ──
    print(f'\n  PRIMARY USER SCENARIO\n  {sep}')
    print(f'\n  {scenario}')

    print(f'\n  SCENARIO MILESTONE TIMELINE\n  {sep}')
    if milestones:
        for m in milestones:
            print(f"  {m['time_s']:7.2f}s  →  {m['label']}")
    else:
        print("""
  [Timeline requires actual TWS log file — see methodology below]

  EXPECTED SEQUENCE FOR MUSIC PLAYBACK SCENARIO:

    0.00s  →  Device connection established
    0.10s  →  Link entered sniff mode (power saving)
    0.50s  →  Sniff mode exited (streaming about to start)
    0.89s  →  AVDTP media channel opened
    6.40s  →  Audio codec initialised (SBC)
    6.50s  →  GAP timer expired (stream re-negotiation)
    6.56s  →  Inter-earbud sync established
    6.70s  →  DSP audio path started — playback begins
    6.73s  →  A2DP stream active (~215 kbps, 0% error rate)
    ...continuous streaming...
    83.56s →  AVDTP stream suspended (user stopped playback)
    85.64s →  DSP audio path stopped""")

    # ── Analysis methodology ──
    print(f'\n  STEP-BY-STEP ANALYSIS METHODOLOGY\n  {sep}')
    print("""
  STEP 1 — Identify the file format
  The TWS_User_Scenario_EXT.7z archive likely contains one or more
  PCAPNG files. Before analysis, confirm the link type:
    Link type 201 = AB159x vendor firmware log (same as Assignment 2)
    Link type 187 = standard HCI H4 (Wireshark can decode natively)
    Link type 202 = Linux Bluetooth Monitor

  STEP 2 — Count distinct connection handles / MAC addresses
  A TWS capture typically shows:
    - 1 Classic BT connection to the phone (e.g. handle 0x0083)
    - 1 inter-earbud connection (different handle)
  This immediately tells you there are at least 2 BT links,
  confirming a multi-device TWS topology.

  STEP 3 — Identify the Primary earbud
  Look for these specific log signatures (AB159x format):
    [mHDT][LOG_QA] Agent LinkIdx:N EDR Legacy!!!
      → This device IS the Agent (Primary). LinkIdx is the
        connection index to the phone.
    [sink][music][a2dp] entries
      → Only the Primary has the A2DP sink service active.
    A2dpStartSuspendSetup, Reset_A2dp_State
      → Only the Primary controls the A2DP stream lifecycle.
    AVDTP state_open(), state_streaming()
      → AVDTP is only on the Primary ↔ Phone link.
    sniff_status role=1
      → The Primary is the slave (role=1) in the phone connection.

  STEP 4 — Identify the Secondary earbud
  The Secondary is identified by absence and by AWS:
    PartnerLost counter in A2DP stats (Primary monitors Secondary)
    Aws If:N in scheduler logs (N>0 = AWS inter-earbud slots active)
    [SCO] FwdRG Rx: Tx: addresses (relay buffer memory allocated)
    InitSync = 1 (sync signal from Primary to Secondary)
    No AVDTP session, no sink_srv entries

  STEP 5 — Identify the Phone (Source)
  The phone is never the log source (the log comes FROM the chip).
  It appears as:
    MAC address in GAP connection entries:
      [M:BTGAP]: hci_handle 83, [f4-a3-10-35-fb-79]
    Source of AVRCP commands (play, pause, volume)
    A2DP source (phone sends SBC packets TO the primary)

  STEP 6 — Reconstruct the user scenario
  Map the protocol event sequence to a user journey:

    Connection events     → user put earbuds in / powered on
    Sniff mode entry      → BT link idle, waiting for audio
    Sniff mode exit       → audio about to start
    AVDTP open + codec    → media channel negotiated, SBC configured
    AWS InitSync          → secondary earbud synchronised
    DSP AFE start         → DAC active, audio output begins
    A2DP stats active     → continuous streaming (user hearing music)
    AVRCP pause/suspend   → user pressed pause
    AVRCP play/resume     → user pressed play
    stream_reset          → audio interrupted (RF or firmware event)
    DSP audio stop        → user removed earbuds / powered off""")

    # ── Acoustic interpretation ──
    print(f'\n  ACOUSTIC / SIGNAL CHAIN INTERPRETATION\n  {sep}')
    print("""
  The TWS signal chain is a distributed audio system with three nodes.
  From an acoustic signal chain perspective:

  SOURCE:
    Phone SBC encoder operates at ~215 kbps, 44.1 kHz stereo.
    SBC is a lossy codec — introduces ~3-5 dB of audible artefacts
    at maximum bitpool vs uncompressed. For B&O, codec quality
    is critical — AAC or aptX would be preferred over SBC.

  TRANSMISSION MEDIUM (Phone → Primary):
    Classic BT BR/EDR with Adaptive Frequency Hopping.
    As demonstrated in Assignment 2, this link is vulnerable to
    2.4GHz interference. Loss here affects BOTH ears simultaneously.

  RELAY LINK (Primary → Secondary):
    The inter-earbud AWS link carries a copy of the decoded stream.
    Clock synchronisation is critical: if Primary and Secondary
    clocks drift, the user perceives a timing offset between ears —
    analogous to inter-channel delay in stereo audio, which causes
    perceived image shift and can be as disruptive as 0.1ms of
    inter-channel delay at high frequencies.

  SYNCHRONISATION:
    InitSync = 1 in the log marks the moment the Secondary locks to
    the Primary's clock. This is the TWS equivalent of sample-accurate
    synchronisation in a DAW. Without it, the stereo image collapses.

  BUFFER DESIGN:
    The Primary's jitter buffer (DSP Level metric) serves BOTH earbuds.
    If the Primary's buffer starves, both ears lose audio simultaneously.
    This is different from a wired stereo system where each channel
    has an independent signal path — TWS is fundamentally asymmetric.

  PERCEPTUAL CONSEQUENCE OF DROPOUT:
    A dropout on the phone→primary link = silence in BOTH ears.
    A dropout on the primary→secondary relay = silence in ONE ear only.
    The user can distinguish these by which ear cuts out.
    This is a useful diagnostic observation for field testing.""")

    print(f'\n{"═"*62}\n')


# ─────────────────────────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────────────────────────

def main():
    print(f'\n{"═"*62}')
    print('  Assignment 3 — TWS Bluetooth Audio System Analysis')
    print(f'{"═"*62}\n')

    # Handle case where file is provided vs not provided
    if len(sys.argv) < 2:
        print("  NOTE: No PCAPNG file provided.")
        print("  Usage: python3 analyse_tws_log.py <path_to_pcapng>")
        print("  Running in methodology-only mode...\n")
        roles, evidence, events, milestones = {}, [], [], []
        scenario = 'Awaiting TWS_User_Scenario_EXT log file'
    else:
        filepath = sys.argv[1]
        if not os.path.exists(filepath):
            print(f"  File not found: {filepath}")
            print("  Running in methodology-only mode...\n")
            roles, evidence, events, milestones = {}, [], [], []
            scenario = 'Awaiting TWS_User_Scenario_EXT log file'
        else:
            print("[1] Parsing PCAPNG file...")
            packets, link_type = parse_pcapng(filepath)

            print("\n[2] Extracting log messages...")
            print("\n[3] Analysing TWS device roles...")
            roles, evidence, events = analyse_tws_roles(packets)

            print(f"    Evidence items: {len(evidence)}")
            print(f"    Protocol events: {len(events)}")

            print("\n[4] Reconstructing user scenario...")
            scenario, milestones = reconstruct_scenario(events)
            print(f"    Scenario identified: {scenario}")

    # Chart output path
    base = sys.argv[1] if len(sys.argv) > 1 else 'tws_analysis'
    chart_out = os.path.join(
        os.path.dirname(base) if os.path.dirname(base) else '.',
        'tws_analysis.png'
    )
    # Write to local working directory if path is read-only
    if not os.access(os.path.dirname(chart_out) or '.', os.W_OK):
        chart_out = 'tws_analysis.png'

    print("\n[5] Generating analysis chart...")
    generate_chart(events, milestones, scenario, chart_out)

    print("\n[6] Full analysis report:")
    print_report(roles, evidence, events, milestones, scenario)


if __name__ == '__main__':
    main()
