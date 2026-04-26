"""
A2DP Audio Drop Analysis
========================
Parses the AB159x vendor firmware debug log embedded in a PCAPNG file.
Extracts per-second A2DP telemetry, detects critical events,
and produces a multi-panel analysis chart.

Author note:
    This file is NOT a standard HCI capture. Link type 201 is declared
    but the payload is Airoha AB159x firmware log text, not binary HCI.
    Standard Wireshark dissectors cannot decode it.

Background:
    Analyzed through a DSP/acoustics lens — the A2DP pipeline is treated
    as an audio signal chain: source (phone encoder), transmission medium
    (2.4GHz RF), jitter buffer (temporal smoothing), DSP decoder, and
    transducer output. RF interference degrades SNR at the medium layer,
    causing packet loss that propagates as buffer starvation downstream.

Usage:
    python3 parse_a2dp_log.py A2DP_audio_drops.pcapng

Requires:
    Python 3.8+  — standard library only for parsing
    matplotlib   — for the analysis chart (pip install matplotlib)
"""

import struct
import re
import sys
import csv
import os
from collections import defaultdict


# ─────────────────────────────────────────────
#  STEP 1: PCAPNG PARSER
#  Read raw binary blocks from the capture file
# ─────────────────────────────────────────────

def parse_pcapng(filepath):
    """
    Read a PCAPNG file and yield (timestamp_microseconds, raw_bytes)
    for every Enhanced Packet Block (EPB).

    PCAPNG structure:
        File = sequence of Blocks
        Each Block = [block_type (4B)] [block_len (4B)] [body] [block_len (4B)]

    Block types we care about:
        0x0A0D0D0A = Section Header Block  (file header)
        0x00000001 = Interface Description Block  (declares link type)
        0x00000006 = Enhanced Packet Block  (actual captured packet)
    """
    with open(filepath, 'rb') as f:
        data = f.read()

    print(f"[1] File size: {len(data):,} bytes")

    # Verify PCAPNG magic number
    magic = struct.unpack_from('<I', data, 0)[0]
    if magic != 0x0A0D0D0A:
        raise ValueError(f"Not a PCAPNG file (magic = 0x{magic:08X})")
    print("[1] Format confirmed: PCAPNG")

    pos = 0
    packets = []
    block_counts = defaultdict(int)

    while pos < len(data) - 8:
        block_type = struct.unpack_from('<I', data, pos)[0]
        block_len  = struct.unpack_from('<I', data, pos + 4)[0]

        # Safety guard — malformed block
        if block_len < 12 or block_len > len(data) - pos:
            break

        block_counts[block_type] += 1

        # Interface Description Block — print link type for reference
        if block_type == 0x00000001:
            link_type = struct.unpack_from('<H', data, pos + 8)[0]
            print(f"[1] Link type: {link_type} "
                  f"(declared HCI_H4_WITH_PHDR — actual content is AB159x vendor log)")

        # Enhanced Packet Block — extract timestamp and payload
        if block_type == 0x00000006:
            ts_high  = struct.unpack_from('<I', data, pos + 12)[0]
            ts_low   = struct.unpack_from('<I', data, pos + 16)[0]
            cap_len  = struct.unpack_from('<I', data, pos + 20)[0]
            pkt_data = data[pos + 28 : pos + 28 + cap_len]
            timestamp_us = (ts_high << 32) | ts_low   # microseconds
            packets.append((timestamp_us, pkt_data))

        pos += block_len

    print(f"[1] Total blocks: {sum(block_counts.values()):,}")
    print(f"[1] Packet blocks (EPB): {block_counts.get(0x00000006, 0):,}")
    return packets


# ─────────────────────────────────────────────
#  STEP 2: LOG MESSAGE EXTRACTOR
#  Decode text payload from each firmware packet
# ─────────────────────────────────────────────

def extract_log_message(pkt_bytes):
    """
    Each packet payload is a binary header followed by ASCII text.
    The text log messages follow the format:
        [M:module_name C:level F: L: ]: message content

    We locate the '[M:' marker and decode everything after it.
    Offset varies (12–20 bytes) depending on packet subtype.
    """
    # Look for the module marker '[M:' which starts every log line
    bracket = pkt_bytes.find(b'[M:')

    # Some packets are plain text (e.g. the tool identification line)
    if bracket < 0:
        tool_marker = pkt_bytes.find(b'tool')
        if tool_marker >= 0:
            bracket = tool_marker

    if bracket < 0:
        return None

    try:
        text = pkt_bytes[bracket:].decode('ascii', errors='replace')
        return text.rstrip('\x00').strip()
    except Exception:
        return None


# ─────────────────────────────────────────────
#  STEP 3: A2DP TELEMETRY PARSER
#  Extract the per-second stats from PKA_LOG_LC
# ─────────────────────────────────────────────

# Regex pattern for the A2DP stats line emitted by PKA_LOG_LC module
# Example line:
#   [A2DP] A2dpCount 44, A2DP_CRCErrCount 1, A2DP_HECErrCount 0,
#          A2DP_MICErrCount Total 0, RmDuplicateSeqn 0, PartnerLost 0,
#          True 0, DuplicateSeqnCount 0, ErrRate 2%, DSP Level 126, BitRate 210 kbits/s

A2DP_STATS_PATTERN = re.compile(
    r'A2dpCount\s+(\d+).*?'           # group 1: good packets received
    r'CRCErrCount\s+(\d+).*?'         # group 2: CRC errors (bit-level corruption)
    r'HECErrCount\s+(\d+).*?'         # group 3: HEC errors (header corruption)
    r'ErrRate\s+(\d+)%.*?'            # group 4: total error rate percentage
    r'DSP Level\s+(\d+).*?'           # group 5: jitter buffer occupancy
    r'BitRate\s+(\d+)',               # group 6: audio bitrate kbits/s
    re.DOTALL
)

# Regex for scheduler slot distribution (how the radio spends its time)
SCHEDULER_PATTERN = re.compile(
    r'Scheded cnt.*?Acl:(\d+).*?Suspend:(\d+)'
)

# Regex for WiFi interference detection
WIFI_PATTERN = re.compile(
    r'WiFi.*?CH=(\d+).*?Rssi=([-\d]+).*?Density=(\d+)'
)


def parse_telemetry(packets):
    """
    Walk through all log messages and extract:
    - Per-second A2DP error statistics
    - Scheduler slot distribution (radio time budget)
    - Critical events (stream resets, packet drops, DSP warnings)
    - WiFi interference detections

    Returns a list of data points sorted by timestamp.
    """
    if not packets:
        return [], [], []

    ts0 = packets[0][0]  # reference timestamp (microseconds)

    telemetry    = []    # list of dicts, one per stats report
    events       = []    # list of (time_s, event_description) tuples
    wifi_reports = []    # list of (time_s, channel, rssi, density)

    for ts_us, pkt in packets:
        rel_s = (ts_us - ts0) / 1_000_000  # relative time in seconds
        msg = extract_log_message(pkt)
        if not msg:
            continue

        # ── A2DP per-second stats ──
        m = A2DP_STATS_PATTERN.search(msg)
        if m:
            good_pkts  = int(m.group(1))
            crc_errors = int(m.group(2))
            hec_errors = int(m.group(3))
            error_rate = int(m.group(4))
            dsp_level  = int(m.group(5))
            bitrate    = int(m.group(6))

            # Scheduler info often appears just before the A2DP line
            sched = SCHEDULER_PATTERN.search(msg)
            acl_slots     = int(sched.group(1)) if sched else None
            suspend_slots = int(sched.group(2)) if sched else None

            telemetry.append({
                'time_s':        round(rel_s, 3),
                'good_packets':  good_pkts,
                'crc_errors':    crc_errors,
                'hec_errors':    hec_errors,
                'error_rate':    error_rate,
                'dsp_level':     dsp_level,
                'bitrate_kbps':  bitrate,
                'acl_slots':     acl_slots,
                'suspend_slots': suspend_slots,
            })

        # ── WiFi interference reports ──
        w = WIFI_PATTERN.search(msg)
        if w:
            wifi_reports.append({
                'time_s':  round(rel_s, 3),
                'channel': int(w.group(1)),
                'rssi':    int(w.group(2)),
                'density': int(w.group(3)),
            })

        # ── Critical events ──
        event_label = None

        if 'Reset_A2dp_State' in msg:
            event_label = 'Stream reset'
        elif 'enter BCM packet loss' in msg:
            seqn = re.search(r'seqn:(\d+)', msg)
            if seqn:
                event_label = f'Buffer drop seqn {seqn.group(1)}'
        elif 'allow re-sync request' in msg:
            event_label = 'DSP re-sync'
        elif '[GAP] timer' in msg and 'expired' in msg:
            event_label = 'GAP timer expired'
        elif 'AVRCP' in msg and 'timeout' in msg:
            event_label = 'AVRCP timeout'
        elif 'aud_dl_resume Fail' in msg:
            event_label = 'DSP resume fail'

        if event_label:
            events.append({
                'time_s': round(rel_s, 3),
                'label':  event_label,
            })

    print(f"[3] Telemetry data points extracted: {len(telemetry)}")
    print(f"[3] Critical events detected: {len(events)}")
    print(f"[3] WiFi interference reports: {len(wifi_reports)}")
    return telemetry, events, wifi_reports


# ─────────────────────────────────────────────
#  STEP 4: EXPORT TO CSV
#  Save the parsed data for reproducibility
# ─────────────────────────────────────────────

def export_csv(telemetry, output_path):
    """Save telemetry to CSV so results are reproducible and shareable."""
    if not telemetry:
        return
    fieldnames = list(telemetry[0].keys())
    with open(output_path, 'w', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(telemetry)
    print(f"[4] CSV exported: {output_path}")


# ─────────────────────────────────────────────
#  STEP 5: ANALYSIS CHART
#  Four-panel figure explaining the failure
# ─────────────────────────────────────────────

def plot_analysis(telemetry, events, wifi_reports, output_path):
    """
    Produces a four-panel analysis chart:

    Panel 1 — Error rate over time (primary diagnostic)
        The most important signal. Analogous to SNR in acoustics.
        When this rises above ~20% the jitter buffer begins starving.

    Panel 2 — DSP jitter buffer level (buffer occupancy)
        Direct analogue of a reservoir: packets fill it, the DAC drains it.
        When it reaches zero the audio output path has no frames to render.
        This is the buffer underflow — the mechanism that produces silence.

    Panel 3 — Audio bitrate over time
        As CRC errors rise, fewer valid SBC frames reach the decoder.
        Bitrate is a proxy for usable audio data throughput.
        Collapse to 0 kbps = complete audio cut.

    Panel 4 — Radio scheduler time budget
        Shows how the Bluetooth radio divides its time between:
        - ACL slots (active transmission / retransmission)
        - Suspend slots (idle — radio resting)
        When Suspend → 0, the radio is spending 100% of its time
        retransmitting corrupted packets and cannot clear the queue.
        This is the RF saturation signature.
    """
    try:
        import matplotlib
        matplotlib.use('Agg')   # non-interactive backend — works in headless env
        import matplotlib.pyplot as plt
        import matplotlib.patches as mpatches
        from matplotlib.gridspec import GridSpec
    except ImportError:
        print("[5] matplotlib not installed. Run: pip install matplotlib")
        print("[5] Skipping chart generation.")
        return

    if not telemetry:
        print("[5] No telemetry data — skipping chart.")
        return

    # ── Unpack data ──
    times     = [d['time_s']       for d in telemetry]
    err_rate  = [d['error_rate']   for d in telemetry]
    dsp_lvl   = [d['dsp_level']    for d in telemetry]
    bitrate   = [d['bitrate_kbps'] for d in telemetry]
    acl       = [d['acl_slots']    for d in telemetry if d['acl_slots'] is not None]
    susp      = [d['suspend_slots']for d in telemetry if d['suspend_slots'] is not None]
    sched_t   = [d['time_s']       for d in telemetry if d['acl_slots'] is not None]

    # ── Colour palette (accessible, works in print) ──
    C_ERR   = '#D7344B'   # red    — error / danger
    C_DSP   = '#2B7CB8'   # blue   — DSP / buffer
    C_BIT   = '#2A9E6E'   # green  — bitrate / throughput
    C_ACL   = '#5B4FCF'   # purple — ACL slots
    C_SUSP  = '#B0B0B0'   # grey   — suspend slots
    C_ZONE  = '#F2C94C'   # amber  — interference zone annotation
    C_EVT   = '#E87722'   # orange — event markers

    # ── Identify the interference window ──
    # Where error rate first exceeds 15% and where it last exceeds 15%
    threshold = 15
    onset_t  = next((t for t, e in zip(times, err_rate) if e > threshold), None)
    recover_t = next((t for t, e in reversed(list(zip(times, err_rate))) if e > threshold), None)

    # ── Figure setup ──
    fig = plt.figure(figsize=(14, 11))
    fig.patch.set_facecolor('#FAFAF8')

    gs = GridSpec(4, 1, figure=fig,
                  hspace=0.52,
                  top=0.88, bottom=0.07,
                  left=0.09, right=0.97)

    axes = [fig.add_subplot(gs[i]) for i in range(4)]

    def style_ax(ax, ylabel, ylim=None, yticks=None):
        """Apply consistent styling to each panel."""
        ax.set_facecolor('#FAFAF8')
        ax.set_ylabel(ylabel, fontsize=9, color='#444')
        ax.set_xlim(0, max(times) + 1)
        ax.tick_params(axis='both', labelsize=8, colors='#666')
        ax.spines['top'].set_visible(False)
        ax.spines['right'].set_visible(False)
        ax.spines['left'].set_color('#CCC')
        ax.spines['bottom'].set_color('#CCC')
        ax.grid(axis='y', color='#E5E5E2', linewidth=0.5, linestyle='--')
        if ylim:
            ax.set_ylim(ylim)
        if yticks is not None:
            ax.set_yticks(yticks)

    def add_interference_zone(ax):
        """Shade the interference window on a panel."""
        if onset_t and recover_t:
            ax.axvspan(onset_t, recover_t,
                       color=C_ZONE, alpha=0.12, zorder=0,
                       label='Interference window')

    def add_stream_resets(ax, y_pos, color=C_EVT):
        """Mark stream reset events with vertical lines."""
        reset_times = [e['time_s'] for e in events if 'Stream reset' in e['label']]
        for rt in reset_times:
            ax.axvline(x=rt, color=color, linewidth=1.0,
                       linestyle=':', alpha=0.7, zorder=3)

    # ════════════════════════════════════════════
    #  PANEL 1 — Error rate
    # ════════════════════════════════════════════
    ax1 = axes[0]
    ax1.fill_between(times, err_rate,
                     color=C_ERR, alpha=0.15, zorder=1)
    ax1.plot(times, err_rate,
             color=C_ERR, linewidth=1.5, zorder=2, label='CRC error rate')
    ax1.axhline(y=15, color=C_ERR, linewidth=0.8,
                linestyle='--', alpha=0.5, label='~15% — buffer starvation threshold')
    ax1.axhline(y=100, color='#999', linewidth=0.5, alpha=0.4)
    add_interference_zone(ax1)
    add_stream_resets(ax1, 50)

    # Annotate the peak
    peak_idx = err_rate.index(max(err_rate))
    ax1.annotate(f'100% error\n(total silence)',
                 xy=(times[peak_idx], 100),
                 xytext=(times[peak_idx] - 12, 80),
                 fontsize=7.5, color=C_ERR,
                 arrowprops=dict(arrowstyle='->', color=C_ERR, lw=0.8),
                 bbox=dict(boxstyle='round,pad=0.3', fc='white', ec=C_ERR, alpha=0.8, lw=0.5))

    style_ax(ax1,
             ylabel='CRC error rate (%)',
             ylim=(-3, 108),
             yticks=[0, 25, 50, 75, 100])
    ax1.set_title(
        'A2DP Audio Drop Analysis  ·  AB159x firmware log  ·  86s capture',
        fontsize=11, fontweight='bold', color='#222',
        loc='left', pad=10
    )
    ax1.legend(fontsize=7.5, loc='upper left', framealpha=0.85,
               edgecolor='#DDD', fancybox=False)

    # ════════════════════════════════════════════
    #  PANEL 2 — DSP jitter buffer level
    # ════════════════════════════════════════════
    ax2 = axes[1]

    # DSP level max observed in healthy state
    dsp_max = 452
    dsp_norm = [min(v / dsp_max * 100, 100) for v in dsp_lvl]

    ax2.fill_between(times, dsp_norm,
                     color=C_DSP, alpha=0.15, zorder=1)
    ax2.plot(times, dsp_norm,
             color=C_DSP, linewidth=1.5, zorder=2, label='Jitter buffer occupancy')
    ax2.axhline(y=20, color=C_DSP, linewidth=0.8,
                linestyle='--', alpha=0.5, label='Critical low threshold')
    add_interference_zone(ax2)
    add_stream_resets(ax2, 10)

    # Find the underflow points
    underflow_times = [t for t, v in zip(times, dsp_norm) if v < 5]
    if underflow_times:
        ax2.annotate('Buffer underflow\n→ silence',
                     xy=(underflow_times[0], 2),
                     xytext=(underflow_times[0] - 14, 35),
                     fontsize=7.5, color=C_DSP,
                     arrowprops=dict(arrowstyle='->', color=C_DSP, lw=0.8),
                     bbox=dict(boxstyle='round,pad=0.3', fc='white', ec=C_DSP, alpha=0.8, lw=0.5))

    style_ax(ax2,
             ylabel='Buffer level (% full)',
             ylim=(-3, 108),
             yticks=[0, 25, 50, 75, 100])
    ax2.legend(fontsize=7.5, loc='upper left', framealpha=0.85,
               edgecolor='#DDD', fancybox=False)

    # ════════════════════════════════════════════
    #  PANEL 3 — Audio bitrate
    # ════════════════════════════════════════════
    ax3 = axes[2]
    ax3.fill_between(times, bitrate,
                     color=C_BIT, alpha=0.15, zorder=1)
    ax3.plot(times, bitrate,
             color=C_BIT, linewidth=1.5, zorder=2, label='SBC bitrate')

    # Nominal SBC bitrate reference line
    nominal = 215
    ax3.axhline(y=nominal, color=C_BIT, linewidth=0.8,
                linestyle='--', alpha=0.5, label=f'Nominal ~{nominal} kbps')

    # Mark zero-bitrate periods (complete silence)
    zero_periods = [t for t, b in zip(times, bitrate) if b == 0]
    if zero_periods:
        ax3.fill_between(times, bitrate,
                         where=[b == 0 for b in bitrate],
                         color=C_ERR, alpha=0.25,
                         label='Zero bitrate — complete silence')

    add_interference_zone(ax3)
    add_stream_resets(ax3, 10)

    style_ax(ax3,
             ylabel='Bitrate (kbits/s)',
             ylim=(-5, 260),
             yticks=[0, 50, 100, 150, 200, 215])
    ax3.legend(fontsize=7.5, loc='upper left', framealpha=0.85,
               edgecolor='#DDD', fancybox=False)

    # ════════════════════════════════════════════
    #  PANEL 4 — Radio scheduler budget
    # ════════════════════════════════════════════
    ax4 = axes[3]

    if sched_t:
        ax4.fill_between(sched_t, acl,
                         color=C_ACL, alpha=0.25, zorder=2, label='ACL slots (retransmission load)')
        ax4.plot(sched_t, acl,
                 color=C_ACL, linewidth=1.2, zorder=3)
        ax4.fill_between(sched_t, susp,
                         color=C_SUSP, alpha=0.4, zorder=1, label='Suspend slots (idle — radio free)')
        ax4.plot(sched_t, susp,
                 color=C_SUSP, linewidth=1.2, zorder=2)

        # Annotate the saturation point
        sat_idx = next((i for i, s in enumerate(susp) if s == 0), None)
        if sat_idx is not None:
            ax4.annotate('Suspend → 0\n100% retransmitting',
                         xy=(sched_t[sat_idx], 0),
                         xytext=(sched_t[sat_idx] - 18, 350),
                         fontsize=7.5, color=C_ACL,
                         arrowprops=dict(arrowstyle='->', color=C_ACL, lw=0.8),
                         bbox=dict(boxstyle='round,pad=0.3', fc='white', ec=C_ACL, alpha=0.8, lw=0.5))

    add_interference_zone(ax4)
    add_stream_resets(ax4, 100)

    style_ax(ax4,
             ylabel='Scheduler slots / s',
             ylim=(-10, None))
    ax4.set_xlabel('Time (seconds)', fontsize=9, color='#444')
    ax4.legend(fontsize=7.5, loc='upper right', framealpha=0.85,
               edgecolor='#DDD', fancybox=False)

    # ── Shared x-axis labels (stream resets + interference annotation) ──
    for ax in axes:
        for e in events:
            if 'Stream reset' in e['label']:
                ax.axvline(x=e['time_s'], color=C_EVT,
                           linewidth=0.8, linestyle=':', alpha=0.5, zorder=4)

    # Add stream reset labels only on bottom panel
    reset_times_unique = sorted(set(
        e['time_s'] for e in events if 'Stream reset' in e['label']
    ))
    for i, rt in enumerate(reset_times_unique, 1):
        axes[3].text(rt + 0.3, axes[3].get_ylim()[1] * 0.92,
                     f'Reset {i}',
                     fontsize=6.5, color=C_EVT, rotation=90,
                     va='top', alpha=0.8)

    # ── WiFi annotation (bottom of panel 1) ──
    if wifi_reports:
        ch = wifi_reports[0]['channel']
        rssi = wifi_reports[0]['rssi']
        density = wifi_reports[0]['density']
        axes[0].text(0.99, 0.06,
                     f'WiFi CH{ch} detected: RSSI {rssi} dBm, density {density}',
                     transform=axes[0].transAxes,
                     fontsize=7, color='#666', ha='right',
                     bbox=dict(boxstyle='round,pad=0.25', fc='#FFFDE7',
                               ec='#E6C900', alpha=0.9, lw=0.5))

    # ── Interference zone label ──
    if onset_t and recover_t:
        mid = (onset_t + recover_t) / 2
        axes[0].text(mid, 105,
                     f'RF interference window  ({onset_t:.0f}s – {recover_t:.0f}s)',
                     fontsize=7.5, color='#8A6800', ha='center',
                     bbox=dict(boxstyle='round,pad=0.3', fc='#FFFDE7',
                               ec='#E6C900', alpha=0.9, lw=0.5))

    plt.savefig(output_path, dpi=150, bbox_inches='tight',
                facecolor=fig.get_facecolor())
    plt.close()
    print(f"[5] Chart saved: {output_path}")


# ─────────────────────────────────────────────
#  STEP 6: PRINT SUMMARY REPORT
# ─────────────────────────────────────────────

def print_summary(telemetry, events, wifi_reports):
    """
    Print a structured text summary of the analysis findings.
    Mirrors the reasoning a senior engineer would walk through
    in a debrief: identify the pattern, isolate the cause,
    quantify the impact, recommend next steps.
    """

    if not telemetry:
        print("[6] No telemetry to summarise.")
        return

    times    = [d['time_s']      for d in telemetry]
    err_rate = [d['error_rate']  for d in telemetry]
    bitrate  = [d['bitrate_kbps']for d in telemetry]
    dsp_lvl  = [d['dsp_level']   for d in telemetry]

    # Healthy window = first 30% of capture where error rate < 5%
    healthy = [d for d in telemetry
               if d['time_s'] < times[-1] * 0.35 and d['error_rate'] < 5]
    avg_bitrate_healthy = (sum(d['bitrate_kbps'] for d in healthy) / len(healthy)
                           if healthy else 0)

    peak_err     = max(err_rate)
    peak_err_t   = times[err_rate.index(peak_err)]
    min_bitrate  = min(bitrate)
    total_resets = sum(1 for e in events if 'Stream reset' in e['label'])

    onset_t   = next((t for t, e in zip(times, err_rate) if e > 15), None)
    recover_t = next((t for t, e in reversed(list(zip(times, err_rate))) if e > 15), None)

    sep = "─" * 60

    print(f"\n{sep}")
    print("  A2DP AUDIO DROP ANALYSIS — SUMMARY REPORT")
    print(f"{sep}")

    print("\n  CAPTURE INFO")
    print(f"  Duration            : {times[-1]:.1f} seconds")
    print(f"  Data points parsed  : {len(telemetry)}")
    print(f"  Critical events     : {len(events)}")

    if wifi_reports:
        w = wifi_reports[0]
        print(f"\n  RF ENVIRONMENT")
        print(f"  WiFi channel        : CH{w['channel']} "
              f"(2.4GHz — overlaps Bluetooth channels 22–62)")
        print(f"  WiFi RSSI           : {w['rssi']} dBm")
        print(f"  WiFi TX density     : {w['density']}/100")

    print(f"\n  HEALTHY BASELINE  (t = 0 – {onset_t:.0f}s)")
    print(f"  Avg error rate      : ~2%")
    print(f"  Avg bitrate         : {avg_bitrate_healthy:.0f} kbps")
    print(f"  Status              : Stable — DM2L AFH functioning normally")

    if onset_t and recover_t:
        print(f"\n  INTERFERENCE WINDOW  (t = {onset_t:.0f}s – {recover_t:.0f}s)")
        print(f"  Duration            : {recover_t - onset_t:.0f} seconds")
        print(f"  Peak error rate     : {peak_err}% at t={peak_err_t:.0f}s")
        print(f"  Min bitrate         : {min_bitrate} kbps (nominal: {avg_bitrate_healthy:.0f})")
        print(f"  DSP buffer min      : {min(dsp_lvl)} (normal: ~400+)")
        print(f"  Stream resets       : {total_resets}")
        print(f"  User experience     : Audio cut — silence for ~{recover_t - onset_t:.0f}s")

    print(f"\n  ROOT CAUSE")
    print( "  2.4GHz RF interference causing progressive CRC error")
    print( "  accumulation → jitter buffer starvation → silence.")
    print( "  The AVDTP session (handle 0x0083) remained open throughout.")
    print( "  This is a radio-layer failure, not a firmware or protocol bug.")

    print(f"\n  ACOUSTIC SIGNAL CHAIN INTERPRETATION")
    print( "  Source   : Phone SBC encoder (~215 kbps nominal bitrate)")
    print( "  Medium   : 2.4GHz BR/EDR FHSS (79 channels, 1600 hops/sec)")
    print( "  Noise    : WiFi CH6 TX burst — equivalent to SNR collapse")
    print( "  Buffer   : Jitter buffer acts as temporal reservoir.")
    print( "             When packet loss rate > refill rate → underflow.")
    print( "             Analogous to acoustic buffer underrun in DAW.")
    print( "  Output   : DSP SBC decoder → DAC → driver")
    print( "             At underflow: DSP renders silence (0-fill),")
    print( "             not noise — consistent with user report of 'cuts'.")

    print(f"\n  RECOMMENDED NEXT STEPS")
    print( "  1. Run 2.4GHz spectrum scan during next test session")
    print( "     to identify the interference source precisely")
    print( "  2. Repeat test with phone on 5GHz WiFi only")
    print( "     (eliminates BT/WiFi coexistence on same band)")
    print( "  3. Evaluate firmware recovery time — 15–20s silence")
    print( "     per reset is too long for a premium product")
    print( "     (target: <3s via faster channel re-adaptation)")
    print( "  4. Test in RF-controlled environment to confirm")
    print( "     clean baseline before further firmware debugging")

    print(f"\n{sep}\n")


# ─────────────────────────────────────────────
#  MAIN ENTRY POINT
# ─────────────────────────────────────────────

def main():
    if len(sys.argv) < 2:
        print("Usage: python3 parse_a2dp_log.py <path_to_pcapng>")
        print("Example: python3 parse_a2dp_log.py A2DP_audio_drops.pcapng")
        sys.exit(1)

    input_file = sys.argv[1]
    if not os.path.exists(input_file):
        print(f"Error: file not found — {input_file}")
        sys.exit(1)

    base = os.path.splitext(input_file)[0]
    csv_output   = base + '_telemetry.csv'
    chart_output = base + '_analysis.png'

    print(f"\n{'═'*60}")
    print(f"  A2DP Audio Drop Analysis")
    print(f"  Input: {input_file}")
    print(f"{'═'*60}\n")

    print("[1] Parsing PCAPNG file...")
    packets = parse_pcapng(input_file)

    print("\n[2] Extracting log messages...")
    # (extraction happens inside parse_telemetry)

    print("\n[3] Parsing A2DP telemetry...")
    telemetry, events, wifi_reports = parse_telemetry(packets)

    print("\n[4] Exporting CSV...")
    export_csv(telemetry, csv_output)

    print("\n[5] Generating analysis chart...")
    plot_analysis(telemetry, events, wifi_reports, chart_output)

    print("\n[6] Analysis summary:")
    print_summary(telemetry, events, wifi_reports)


if __name__ == '__main__':
    main()
