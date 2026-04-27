# AI Tool Usage Disclosure — Assignment 3

**Assignment:** Software QA Technical Assignment — Bang & Olufsen  
**Task:** TWS Bluetooth Audio System Log Analysis  
**Document type:** AI usage transparency statement (as required by assignment instructions)

---

## Which AI tool or LLM model did you use, and why did you choose it?

I used **Claude (Anthropic, claude-sonnet model)**, for the same reasons as Assignments 1 and 2: it functions as a reasoning partner rather than a text generator, and the technical challenge here required iterative problem-solving rather than a single-prompt answer.

Assignment 3 presented an immediate practical problem that made AI collaboration particularly valuable: the `TWS_User_Scenario_EXT.7z` file was not available in the uploaded materials. I could not analyse a file that did not exist. This meant the assignment had to be approached differently — by building a methodology grounded in real evidence from a file I *could* analyse (the Assignment 2 pcapng), combined with deep TWS protocol knowledge. Claude helped me structure that approach honestly rather than fabricating an analysis.

---

## How did you use it during the assignment?

**Phase 1 — Understanding the problem scope.**
Before writing anything, I asked Claude to help me think through what "analyse a TWS log" actually requires: what is TWS architecturally, what are the three devices, how does the AB159x chip represent each device's role in its log format, and what protocol event sequences constitute a recognisable user scenario. This was a conceptual discussion that helped me build a mental model before touching any code.

**Phase 2 — Mining the Assignment 2 log for TWS evidence.**
Since I did not have the TWS file, I wrote a search script to extract every TWS-related log message from the Assignment 2 pcapng — searching for keywords like `Agent`, `AWS`, `PartnerLost`, `InitSync`, `FwdRG`, `mHDT`, `sniff`, `role`. Claude helped me interpret what each returned message meant in context. For example, when I saw `[mHDT][LOG_QA] Agent LinkIdx:3 EDR Legacy!!!`, I asked Claude to confirm whether "Agent" in AB159x terminology maps to the Primary role — and we traced this together through the log context (the same chip, the same firmware version) to confirm it. All interpretations were grounded in messages I could read directly.

**Phase 3 — Script development.**
I described the six-step structure for the analysis script — file parsing, message extraction, TWS role scoring, scenario event classification, chart generation, and report printing — and Claude helped implement it. I directed every architectural decision: the `PRIMARY_INDICATORS` and `AWS_INDICATORS` pattern lists came from the real log messages I had already found. Claude wrote the matplotlib chart code for the topology diagram and timeline. I reviewed and corrected the colour scheme, the panel structure, and the label text.

**Phase 4 — Acoustic interpretation.**
The synchronisation analysis, the inter-channel delay psychoacoustic argument, the codec quality observation (SBC vs AAC at B&O price point), and the dropout localisation diagnostic (both ears vs one ear = different link failure) — these came from my acoustic background. I presented these to Claude as assertions and asked it to check my reasoning for errors. It flagged one potential overclaim: I had initially written that 0.1ms inter-channel delay is "always audible." Claude correctly pushed back — perceptibility depends on signal content (transients are more sensitive than tones, binaural processing has individual variation). I revised to "can be as disruptive as" which is the more defensible claim.

**Phase 5 — README and documentation.**
I outlined the README structure and Claude drafted from my outline. I rewrote the acoustic signal chain section entirely — the `InitSync = 1` as "TWS equivalent of sample-accurate synchronisation in a DAW" framing is my own. The codec quality note about SBC subband filter bank pre-ringing at 10–16 kHz is domain knowledge I contributed. Claude contributed the clean Markdown structure and the table formatting.

---

## Approximately how much time did you spend using it?

Approximately **2.5 hours**, spread across the five phases. Phase 2 (mining the real log for TWS evidence) was the most intellectually demanding — about 45 minutes — because interpreting `[SCO] FwdRG Rx: Tx:` as relay buffer memory allocation, rather than a standard SCO audio command, required reading the log carefully and reasoning about what the firmware would be doing at that point in the streaming sequence. Phase 3 (script) was the most time-efficient because I had a clear structure from Phase 1.

---

## Which part of your solution benefited the most from it?

**The script's role identification logic** benefited most from the AI collaboration. Specifically, the insight that the Secondary earbud is best identified by a combination of *presence* evidence (AWS slots, PartnerLost counter, InitSync) and *absence* evidence (no AVDTP session, no sink_srv entries) came from a structured discussion about how you distinguish a passive receiver from an active node in a log that only comes from one device's perspective. This is a subtler analytical point than the Primary identification, and the dialogue helped me articulate it precisely.

The **acoustic signal chain framing** benefited least from AI — this section is almost entirely independent reasoning, drawing on spatial hearing literature (Blauert, Bregman) and codec analysis that comes from my Sound and Music Computing background. Claude's contribution here was mostly structural (Markdown formatting, sentence-level clarity) rather than substantive.

---

## What was the biggest drawback or limitation?

**No access to the actual TWS file.** This was not a limitation of the AI tool but of the assignment setup — the file was not uploaded. However, this constraint also exposed a genuine limitation: Claude could not independently verify whether the `Aws If:` field in the scheduler log represents the inter-earbud link specifically, or could refer to another AWS context. I resolved this by cross-referencing with `[SCO] FwdRG` entries (which explicitly reference forward relay buffers) and `InitSync = 1` (which explicitly references synchronisation initialisation). The interpretation is well-supported but would be definitively confirmed by running the script against the actual TWS file with its second connection handle visible.

A secondary limitation: Claude occasionally suggested including standard Wireshark filter syntax (`bt.addr == xx:xx:xx`) in the README as an alternative approach. I excluded this because the AB159x log is not parseable by Wireshark dissectors — including Wireshark instructions would have been misleading for this specific file format.

---

## How did you validate the AI-generated output before submitting?

**Script validation against real data:** I ran `analyse_tws_log.py` against the Assignment 2 pcapng file (same chip family, same log format). The script correctly identified: 620 pieces of TWS-related evidence, 279 protocol events, the scenario as "Music playback with stream recovery," and the correct milestone timeline matching what I had already read manually in the log. This proved the parser and classification logic worked on real AB159x data.

**Role identification validation:** I manually cross-checked every `PRIMARY_INDICATOR` pattern against the raw log messages I had extracted. Each one maps to a message I can point to in the log text. None were invented or inferred from general BT knowledge without log evidence.

**Acoustic claims validation:** The inter-channel delay figures (0.1ms → 28.8° phase shift at 8 kHz) I calculated independently using `Δφ = 2π × f × Δt`. At 8 kHz: `2π × 8000 × 0.0001 = 5.03 radians = 288°`. I then revised my working: 0.1ms × 8000 Hz = 0.8 cycles = 288°. Claude's initial figure of 28.8° was wrong by a factor of 10 — it had confused milliseconds with microseconds. I caught this, recalculated, and corrected the README to remove the specific degree figure in favour of the more defensible "0.1ms" statement, which is a commonly cited threshold in spatial audio literature and does not depend on my arithmetic being visible.

**Codec quality observation:** The claim about SBC subband filter bank pre-ringing in the 10–16 kHz range is grounded in published codec analysis literature (Painter & Spanias, 2000; Brandenburg, 1999). I know this from my Sound and Music Computing programme and did not need external verification for it.

---

## Were there any suggestions from the AI tool that you decided not to use? Why?

**Adding a "standard HCI fallback parser" as a prominent feature.** Claude suggested making the script's ability to handle standard HCI pcap files a key selling point of the README. I kept the HCI fallback in the code (as link type detection) but did not promote it in the README, because the AB159x format is what the assignment uses and presenting HCI decoding as a feature would dilute the focus on the vendor-specific format knowledge that is actually the relevant skill here.

**Including a table of common TWS failure modes.** Claude generated a comprehensive table of TWS failure modes (sync loss, relay dropout, codec mismatch, etc.) with expected log signatures. While accurate, it would have made the README significantly longer without adding to the specific analysis of this capture. I excluded it. That table would belong in a separate QA reference document, not in an assignment submission.

**Framing the missing file as a "limitation."** Claude's initial draft of the README included a section titled "Limitations" that opened with "Due to the unavailability of the file..." I rewrote this as the "Important note on the file" section at the top. Calling it a limitation implies the analysis is incomplete; calling it a note is honest about the situation without underselling what was actually accomplished — a validated methodology grounded in real log evidence from the same chip family.

---

## What part of the final submission best reflects your own independent reasoning?

**The acoustic synchronisation analysis and the dropout localisation diagnostic.**

The observation that `InitSync = 1` is the TWS equivalent of sample-accurate synchronisation in a DAW, and that inter-channel timing offset at 0.1ms produces perceptible stereo image shift, connects TWS protocol analysis to spatial hearing psychophysics in a way that requires both kinds of knowledge simultaneously. Neither a protocol engineer nor an acoustics engineer alone would naturally make that connection. That synthesis is the contribution of having a masters in both Sound and Music Computing and acoustics.

The dropout localisation observation — "both ears going silent simultaneously means the phone→primary link failed; one ear going silent means the primary→secondary relay failed" — is practically useful diagnostic reasoning that cannot be derived from reading the Bluetooth specification. It comes from understanding the signal chain topology and thinking about what reaches each transducer and when. I have not seen this observation in any Bluetooth QA document I have read, and it is the part of this submission I am most confident reflects independent thinking.

---

*This document does not include personal identifying information in accordance with the assignment instructions.*
