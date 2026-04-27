# AI Tool Usage Disclosure — Assignment 3 (Real Files)

**Assignment:** Software QA Technical Assignment — Bang & Olufsen  
**Task:** TWS Bluetooth Audio System Log Analysis — Device_1/2/3.pcapng  
**Document type:** AI usage transparency statement

---

## Which AI tool or LLM model did you use, and why did you choose it?

I used **Claude (Anthropic, claude-sonnet model)**, consistent with Assignments 1 and 2.

I needed a coding partner who could help me process large binary files efficiently, reason about ambiguous log evidence, and structure findings coherently. Claude served that role.

---

## How did you use it during the assignment?

**Phase 1 — Format reconnaissance and timestamp alignment.**  
I first asked Claude to help me write inspection code to determine file sizes, packet counts, link types, and crucially, the absolute timestamps in all three files. The finding that all three captures ended within 4 seconds of each other — despite Device 3 starting 31 minutes later — was the first major analytical result, confirming a coordinated multi-device session. I identified this pattern myself by examining the raw timestamp numbers; Claude helped write the struct-based parser to extract them.

**Phase 2 — Module inventory before reading messages.**  
Rather than jumping to message content, I directed Claude to help me extract the unique module names active in each file first. This was my methodology — establish the device identity from the firmware architecture before reading individual log lines. The module inventory alone told the story: `BEO_KEY_REMAPPER` and `APP_FORCE_SENSOR` in Device 1 (primary, user-facing), `BEO_RELAY` and `Partner RX_BT3_MIC_ERROR` in Device 2 (secondary relay receiver), `DONGLE_AIR` and `USBAUDIO_DRV` in Device 3 (USB dongle). Claude implemented the extraction; I interpreted the meaning of each module name.

**Phase 3 — Role confirmation through targeted log mining.**  
I defined a list of role-defining patterns based on what I expected to find in an AB1585/88 log (from reading the Assignment 2 logs and understanding the Airoha chip family). I asked Claude to implement pattern matching against all three files simultaneously and score each device against each role. The hex role values `0x40` (Agent) and `0x20` (Partner) appearing explicitly in log messages were particularly significant — I identified these as definitive role markers and Claude confirmed they appear consistently in the right devices.

**Phase 4 — Scenario reconstruction.**  
The most analytically interesting discovery — that this was a firmware OTA session, not a music listening session — emerged from looking at the timeline of `BEO_UPGRADE_*` module activity. I noticed these modules appearing from early in the session and persisting throughout. I asked Claude to build a unified timeline merging all three device event streams by wall-clock timestamp, which revealed the four-phase session structure. The OTA interpretation and its acoustic implications (flash write latency affecting DSP scheduling) are my own domain reasoning.

**Phase 5 — LE Audio + SIRK identification.**  
The SIRK (`connect_cs, sirk:b6-31-f2-8e-e6-55-d0-31`) in Device 3 logs was identified by me as the LE Audio Coordinated Set identifier — this connects to the Bluetooth 5.2 LE Audio specification knowledge I had from the assignment preparation. I explained to Claude what SIRK is and asked it to include the explanation in the README. Claude wrote the prose; the interpretation is mine.

**Phase 6 — Chart and documentation.**  
I described the chart structure (topology panel + three-lane event timeline), the colour scheme, and the evidence box content. Claude implemented the matplotlib code. I reviewed and corrected the lane labels and the legend.

---

## Approximately how much time did you spend using it?

Approximately **4 hours** of active dialogue, the longest of all three assignments. The large file sizes (128 MB, 66 MB, 67 MB) meant that every script iteration took time to run, and interpreting 1.8 million packets across three concurrent device perspectives required more iterations than the single-device analyses in Assignments 1 and 2.

Phase 2 (module inventory) was fastest — about 20 minutes. Phase 3 (role confirmation across all three devices) was the most time-intensive — about 90 minutes — because the secondary earbud's evidence required understanding the distinction between high AWS slot counts as a secondary signature versus a primary in heavy relay mode. Phase 4 (scenario timeline) took about 60 minutes to produce a readable unified timeline from three asynchronous event streams.

---

## Which part of your solution benefited the most from it?

**The unified timeline construction** across three simultaneous captures benefited most from AI collaboration. Merging three event streams with different start offsets (6 seconds, 0 seconds, 1888 seconds) into a single coherent wall-clock-ordered narrative, then deduplicating within time windows to avoid redundant entries while preserving meaningful events, is a data processing problem where having a coding partner accelerated the work significantly.

**The role confidence scoring** also benefited. Rather than binary role assignment (primary/secondary/dongle), I wanted a percentage score showing how strongly each pattern category pointed to each role. Claude implemented the scoring function; I designed the evidence weight structure by deciding which patterns were most diagnostic.

---

## What was the biggest drawback or limitation?

**The AB1585/88 is a different chip from Assignment 2's AB159x.** While the log format is similar (same vendor, same `[M:module C:level]` structure), the specific module names, log messages, and role indicators differ between chip generations. Claude had no prior knowledge of AB1585/88 specifically — it had only seen AB159x from Assignment 2. Every AB1585/88-specific finding (the `0x40`/`0x20` role hex values, the `@@@ Partner RX_BT3_MIC_ERROR` string, the `lcAWSCTL_HandlePostponeIF` relay control messages, the `BEO_UPGRADE_*` OTA module names) required me to read the actual log messages and tell Claude what they meant before it could use them as evidence.

This is the correct workflow — domain reading first, then tool-assisted analysis. But it means the quality of the analysis is bounded by how carefully I read the logs, not by how much the AI knows about Airoha firmware.

A secondary limitation: with files this large, I could not read every packet. I sampled at 1-in-5 to make the analysis tractable. There may be isolated events between samples that I missed. The key findings (role assignments, OTA scenario, RHO count) are robust because they appear repeatedly throughout the captures, not as single isolated events. But a complete pass at every packet would add confidence.

---

## How did you validate the AI-generated output before submitting?

**Role identification validation:** For each evidence entry in the role scoring output, I traced it back to a specific verbatim log message I had already read. The primary evidence items — `Agent set AWS state`, `aws_role:0x40`, `@@@ Partner RX_BT3_MIC_ERROR`, `DONGLE_AIR` — all appear in raw log output I extracted and verified manually. The role confidence scores (94% primary for D1, 91% secondary for D2, 100% dongle for D3) match the qualitative picture I formed from reading the first 500 messages of each device.

**Timestamp alignment validation:** The wall-clock alignment finding (all three captures ending within 4 seconds) was verified by reading the raw timestamp values from the script output and doing the arithmetic manually: D1 end - D3 end = 1,773,118,326 - 1,773,118,322 = 4,000 µs = 4 seconds. Correct.

**RHO count validation:** I counted `end cm rho gap event` occurrences manually in the sampled output: one at t=455s (Device 2), one at t=1017s (Device 1), one at t=1286s (Device 1). Three total. The side-flip observation — Device 1 reporting Side=2 early and Side=1 late while Device 2 shows the reverse — I verified from the raw log excerpts and it is consistent with three RHOs.

**OTA scenario validation:** The `Apply upgrade and reboot` message at t=3643s on Device 1 is unambiguous — this is a standard Airoha FOTA completion string. I verified it appears verbatim in the raw log output.

**Acoustic interpretation validation:** The SIRK explanation (LE Audio Coordinated Set identification), the AWS slot count asymmetry reasoning (Secondary allocates more AWS slots because it has no phone link), and the OTA+DSP interaction risk are all claims I can defend from first principles. None required external verification.

---

## Were there any suggestions from the AI tool that you decided not to use? Why?

**Adding a signal strength (RSSI) analysis panel to the chart.** Claude suggested adding a fourth chart panel plotting the RSSI values from `PKA_LC: SmartPhone Rssi: -N, IF Rssi: -M` logs over time. While this data exists in the Device 2 logs (the secondary has a direct view of the inter-earbud link quality), a 61-minute RSSI timeline would make the chart visually busy without adding to the role identification or scenario conclusions. I excluded it. It would be appropriate for a dedicated inter-earbud link quality investigation, not for this assignment.

**Describing Device 3 as "charging case with integrated dongle."** Claude's initial framing combined the charging case controller and USB dongle functions into a single compound description. I kept them separate in the evidence table because the log provides independent evidence for each function (`APP_CHARGER_CASE` for case control, `DONGLE_AIR`/`USBAUDIO_DRV` for USB dongle). These may actually be two distinct firmware images on two separate processors within the same physical device — conflating them in the role label would be imprecise.

**Including AWS slot count graphs over time.** The Aws If: values from all three devices could be plotted over time to show the role transitions during RHO (Primary's AWS slots increase post-RHO, Secondary's decrease). Technically interesting but the three-lane event timeline already shows the RHO events clearly. Adding more subplots to an already dense chart would reduce readability.

---

## What part of the final submission best reflects your own independent reasoning?

**The OTA scenario identification and its acoustic implications.**

The identification that this is a firmware OTA session — not a music listening session — required reading a pattern of firmware update module names (`BEO_UPGRADE_LIB`, `BEO_UPGRADE_FLASH`, `BEO_UPGRADE_DATA`) spread across 61 minutes and connecting them to the terminal `"Apply upgrade and reboot"` event. No prompt template or keyword search produces this conclusion directly — it requires recognising the significance of the BEO_UPGRADE module family and knowing that OTA updates involve streaming firmware data to flash while audio continues.

The acoustic consequence I drew — that flash write interrupt latency competes with DSP scheduling and could produce jitter buffer drops indistinguishable from RF interference — comes from understanding how embedded real-time systems schedule competing tasks. This is not a Bluetooth fact; it is a systems engineering observation that requires knowing something about how RTOS scheduling works on resource-constrained audio processors. It also creates a practically important QA test case: audio quality testing must be repeated during an active OTA write cycle, not just during clean streaming.

The SIRK interpretation connecting Device 3's `connect_cs` log entry to the Bluetooth 5.2 LE Audio Coordinated Set specification is also independently reasoned. I knew what SIRK was from assignment preparation; Claude did not prompt it.

---

*This document does not include personal identifying information in accordance with the assignment instructions.*
