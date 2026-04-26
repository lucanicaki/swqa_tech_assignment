# AI Tool Usage Disclosure — Assignment 2

**Assignment:** Software QA Technical Assignment — Bang & Olufsen  
**Task:** A2DP Audio Drop Analysis — Wireshark trace investigation  
**Document type:** AI usage transparency statement (as required by assignment instructions)

---

## Which AI tool or LLM model did you use, and why did you choose it?

I used **Claude (Anthropic, claude-sonnet model)** as a technical collaborator for this assignment.

I chose Claude for the same reason I chose it for Assignment 1 — I wanted a tool capable of reasoning through a problem interactively, not one that generates a formatted answer on the first prompt. For a Wireshark analysis task where the file format itself was the first obstacle, I needed something I could have a real back-and-forth with: "this is what I'm seeing in the bytes, what does it mean?" That kind of iterative technical dialogue is where Claude is strongest.

---

## How did you use it during the assignment?

My workflow had four distinct phases, and Claude's role was different in each.

**Phase 1 — File format identification.**
I knew immediately that the file was not decoding correctly as standard HCI in Wireshark. I asked Claude to help me write a Python PCAPNG binary parser to inspect the raw packet payloads directly. I provided the hex output from the first few packets and Claude helped me identify the `[M:module C:level]` log format and the `AB159x Logging Tool` header in packet zero. This was a collaborative debugging session — I was reading the bytes, Claude was helping me interpret the structure.

**Phase 2 — Parser development.**
Once the format was identified, I worked with Claude to build the six-step Python script: PCAPNG block parser, log message extractor, A2DP telemetry regex parser, CSV exporter, matplotlib chart generator, and summary report printer. I directed the structure — six numbered steps corresponding to how a real engineer would approach the problem — and reviewed every function. Claude wrote the boilerplate and I corrected the domain-specific parts, particularly the regex pattern for the `PKA_LOG_LC` stats line and the acoustic framing of the jitter buffer analysis.

**Phase 3 — Signal chain interpretation.**
This is where my acoustic background took over. I identified the jitter buffer starvation mechanism, the DSP Level metric as a buffer occupancy gauge, and the critical observation that buffer underflow produces silence (zero-fill) rather than noise — which is why the user reported clean "cuts" not crackling. I presented this interpretation to Claude and asked it to challenge my reasoning. It confirmed the logic was sound and suggested adding the scheduler slot analysis (ACL vs Suspend slots) as a supporting layer, which I had not initially included. I validated this against the log data myself before including it.

**Phase 4 — Chart design and README.**
I described the four-panel chart structure to Claude — error rate, buffer occupancy, bitrate, scheduler budget — and explained why those four panels tell a causal story top-to-bottom. Claude implemented the matplotlib code. I reviewed the axis labels, colour choices, annotation placement, and the acoustic signal chain table in the README, editing both for accuracy and framing.

---

## Approximately how much time did you spend using it?

Approximately **3–4 hours** of active dialogue, spread across the four phases. Phase 1 (format identification) was the most time-intensive — roughly 90 minutes — because parsing an undocumented vendor binary format requires a lot of trial-and-error inspection of raw bytes. Phases 2 and 4 (code and README) were faster. Phase 3 (interpretation) was almost entirely independent of Claude.

---

## Which part of your solution benefited the most from it?

**The PCAPNG binary parser** benefited most. Writing a correct `struct`-based parser for an undocumented vendor log format embedded inside a PCAPNG container — with the right byte offsets for the Section Header Block, Interface Description Block, and Enhanced Packet Blocks — is the kind of tedious, precise work where having a coding collaborator saves significant time. The parser logic itself is not acoustics domain knowledge; it is just careful byte arithmetic. Claude handled this well and I validated the output by inspecting the decoded messages against the raw hex manually.

The **acoustic signal chain framing** in the README and the four-panel chart narrative structure reflect my own thinking most directly. These were not generated — they were written by me and checked by Claude for any logical gaps.

---

## What was the biggest drawback or limitation?

Two limitations stood out.

The first was **vendor-specific knowledge.** Claude had no knowledge of the AB159x chip or Airoha's logging format specifically. Everything about the log structure — the `[M:module C:level F: L: ]` format, the meaning of `PKA_LOG_LC`, `DM2L`, `BTAVM`, `strm_a2dp`, `DSP Level`, and `A2dpCount` — had to come from reading the log messages themselves. Claude could help me parse the text once I explained what each field meant, but it could not independently interpret the vendor telemetry. Domain reading was entirely on me.

The second was **a tendency toward generic QA framing.** When asked to review the README, Claude occasionally suggested adding standard QA language ("test coverage", "regression suite") that was not relevant to a hardware-layer RF analysis. I filtered this out and kept the framing grounded in signal chain physics throughout.

---

## How did you validate the AI-generated output before submitting?

Three validation steps, applied to every component.

**Code validation:** I ran the Python script against the actual `A2DP_audio_drops.pcapng` file and checked that the output matched what I could verify manually — 25,630 packets, 75 telemetry data points, the correct WiFi channel (CH6) and RSSI (-84 dBm) from the log, and the correct peak error rate (100% at t=61s). Any discrepancy between the script output and the raw log text I had already read would have indicated a parsing error.

**Data validation:** I cross-referenced the CSV output against the raw log messages for a sample of 10 rows — checking that `A2dpCount`, `CRCErrCount`, `ErrRate`, `DSP Level`, and `BitRate` values in the CSV matched the corresponding log lines exactly.

**Interpretation validation:** The acoustic interpretation — particularly the buffer underflow mechanism and the silence vs noise distinction — I validated against my own understanding of DSP pipeline behaviour from my Sound and Music Computing masters. The claim that a jitter buffer underflow produces silence rather than noise is a fundamental property of how digital audio output paths handle buffer starvation, and I confirmed this independently before including it.

---

## Were there any suggestions from the AI tool that you decided not to use? Why?

Several were set aside.

**A fifth chart panel showing sequence number gaps.** Claude suggested adding a panel plotting the `strm_a2dp` BCM drop sequence numbers to visualise packet loss patterns. While technically interesting, it would have made the chart harder to read without adding to the root cause narrative. The four panels I kept tell a complete causal story. A fifth panel would be detail for an engineering deep-dive, not a QA findings report.

**Framing the AVRCP timeouts as a separate issue.** Claude flagged the AVRCP command timeout events at t=6.56s and t=81.7s as potentially worth investigating independently. After reviewing the log context, I concluded these were artefacts of the same stream restart sequence — not independent failures — and excluded them from the root cause section to avoid diluting the finding.

**Using pyshark instead of a custom parser.** Claude initially suggested using the pyshark library (a Python wrapper for tshark) to decode the file. I rejected this because: (a) pyshark requires Wireshark to be installed; (b) standard Wireshark dissectors cannot decode this vendor format anyway; and (c) writing a custom binary parser demonstrates more directly that I understand the file structure, which is a more honest representation of the analytical work involved.

---

## What part of the final submission best reflects your own independent reasoning?

**The acoustic signal chain interpretation** is the most independently reasoned part of this submission.

The identification of the jitter buffer as a temporal reservoir analogous to a DAW playback buffer, the framing of CRC error rate as a radio-layer SNR metric, the explanation of why underflow produces silence rather than noise, and the connection between the DM2L `SugChMNum=0` event and the concept of a completely saturated noise floor — these are all conclusions I reached by applying knowledge from my acoustic and DSP background to what I was reading in the log.

The signal chain table in the README — mapping each protocol layer to its acoustic analogue — is something I have not seen in any Bluetooth QA document I have read. It came from thinking about the problem the way I was trained to think, not from any template or suggestion. I believe it is also the part of this analysis most likely to be genuinely useful to the B&O engineering team, because it provides a physical intuition for what the metrics mean that a pure protocol-layer analysis does not.

---

*This document does not include personal identifying information in accordance with the assignment instructions.*
