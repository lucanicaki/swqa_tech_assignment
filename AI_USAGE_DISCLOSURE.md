# AI Tool Usage Disclosure

**Assignment:** Software QA Technical Assignment — Bang & Olufsen  
**Document type:** AI usage transparency statement (as required by assignment instructions)

---

## Which AI tool or LLM model did you use, and why did you choose it?

I used **Claude (Anthropic, claude-sonnet model)** as an intellectual sparring partner throughout this assignment.

I chose Claude specifically because I wanted a tool capable of engaging at a conceptual level — one that could challenge my reasoning and push back on assumptions, rather than simply generating structured output on demand. For a QA assignment where the quality of thinking matters more than the formatting of answers, I needed a tool that would function like a knowledgeable peer reviewer rather than a writing assistant.

---

## How did you use it during the assignment?

My use of Claude was **adversarial and iterative**, not generative. The workflow was:

1. **I drafted my analysis first.** For each task, I wrote my own initial response based on my domain knowledge — including acoustic signal chain analysis, Bluetooth protocol understanding, and QA methodology.

2. **I submitted my draft to Claude for challenge.** I explicitly asked Claude to identify gaps, weak reasoning, and anything a senior QA engineer with acoustics knowledge would find insufficient. The prompt was structured as a critique request, not a generation request.

3. **I evaluated the pushback.** Some of Claude's challenges were valid and prompted me to expand or deepen my answer — particularly around the NVM write race decomposition in the bug report and the acoustic measurement criteria in the test cases. Others I rejected because they reflected a generic software QA perspective that didn't account for acoustic domain specifics.

4. **I integrated selectively.** The final submission reflects my own reasoning refined through that dialogue — not Claude's output adopted wholesale.

Claude also helped me verify that my acoustic references were being applied correctly (e.g., that IEC 711 is the appropriate measurement standard for earbud output characterization) and that my Bluetooth protocol assumptions were technically sound.

---

## Approximately how much time did you spend using it?

Approximately **2.5–3 hours** of active dialogue with Claude, distributed across the assignment tasks. The majority of this time was spent on Tasks 1, 4, 5, and 7, where the domain depth warranted the most back-and-forth. Task 3 (test scenarios) required the least AI interaction — scenario design is where my acoustic background gave me the clearest independent direction.

---

## Which part of your solution benefited the most from it?

**Task 5 (Bug Report)** benefited most significantly. My initial bug report identified the state mismatch but described it as a single defect. Claude's challenge prompted me to decompose it into two mechanistically distinct root causes: (a) premature BLE ATT_WRITE_RSP before DSP commit, and (b) asynchronous NVM write occurring after ACK, vulnerable to rapid disconnection. This distinction is not cosmetic — the two defects require separate firmware fixes and different regression test strategies. Once Claude raised the decomposition question, I validated it against my understanding of embedded NVM write patterns, confirmed it was accurate, and restructured the bug report accordingly.

The **acoustic pass/fail criteria in Task 4** also benefited. Claude challenged the vagueness of "verify acoustically" as a test step, which is a legitimate criticism — an executable test case requires numeric pass/fail thresholds. I defined the dB attenuation criteria (>15dB in 100–1000Hz for ANC, <5dB for Transparency) based on my own acoustic knowledge; Claude's challenge surfaced the need to make that explicit in the test case format.

---

## What was the biggest drawback or limitation?

The most significant limitation was **Claude's tendency toward generalist QA framing**. When asked to critique my work, it occasionally suggested additions that were structurally sound but acoustically naive — for example, treating "wind noise in Transparency mode" purely as an environmental interference problem, rather than recognizing it as a feedforward microphone saturation issue rooted in the physical design of the transducer capsule. I had to actively filter suggestions that would have diluted the acoustic specificity of the submission with generic QA language.

A secondary limitation: Claude could not independently verify acoustic measurement standards or confirm IEC 711 applicability without me providing that context. The tool is a strong reasoning partner but not a domain authority — any acoustic claim it generated required validation against my own knowledge or cited standards.

---

## How did you validate the AI-generated output before submitting your final answer?

I applied three validation layers:

1. **Domain cross-check.** Any claim touching DSP behavior, Bluetooth protocol mechanics, or acoustic measurement was verified against my existing knowledge and, where relevant, against the cited references in the documentation file. Claude's assertion about NVM write timing, for example, was validated against embedded systems firmware patterns I'm familiar with from prior work.

2. **Internal consistency check.** I verified that the bug report decomposition (Defect A vs Defect B) was logically consistent with the test case design (TC-02 directly targets the NVM race condition) and the release recommendation (which cites the reconnect mismatch as the primary blocker). If Claude had introduced reasoning that broke this internal consistency, it would have been rejected.

3. **"Would I defend this in a debrief?" test.** For every section, I asked myself whether I could explain and defend the reasoning in a live conversation with the B&O engineering team without referring back to Claude's output. If the answer was no, the content was either reworked in my own framing or removed.

---

## Were there any suggestions from the AI tool that you decided not to use? Why?

Several suggestions were not adopted:

- **Adding an "Accessibility" risk item to Task 1.** Claude suggested flagging accessibility for hearing-impaired users as a missing requirement. While valid in a general product context, this fell outside the scope of the specific feature requirements provided and would have diluted the focused acoustic/protocol risk analysis.

- **Recommending a "conditional release" with heavy caveats as the primary stance in Task 7.** Claude initially framed the release recommendation around conditional release with multiple mitigations. I rejected this as insufficiently decisive for a premium brand context. The NVM state mismatch at a 4% rate is a trust-critical failure — not a risk to be managed with workarounds at launch. I adopted "no release" as the primary recommendation and defined the conditional path as a secondary option for extreme timeline pressure, which is the more honest framing.

- **Including a generic "test on multiple Android OEM devices" scenario as a separate test scenario.** This is standard practice, not a high-value scenario — it does not map to a specific failure mode. It was folded into the test approach section rather than elevated to a named scenario.

---

## What part of the final submission best reflects your own independent reasoning?

**Task 3 (test scenarios), Task 6 (exploratory testing), and the acoustic measurement criteria in Task 4** best reflect independent reasoning.

The test scenarios — particularly TS-02 (switching artifact check with spectrogram analysis), TS-08 (single earbud occlusion effect), and TS-10 (fuel gauge accuracy under DSP load differential) — came directly from acoustic domain knowledge and real-world experience with how premium earbuds fail in practice. These scenarios were not generated or suggested by Claude; I presented them first and Claude's challenge was to find gaps, not to originate them.

The exploratory testing section (Task 6) similarly reflects domain-grounded thinking: the jaw movement / occlusion effect test, the ANC convergence window test, and the perceived ear pressure change observation are acoustic phenomena that come from understanding how the ear canal interacts with feedback-path ANC systems — not from software QA heuristics.

The release recommendation (Task 7) also reflects my own judgment. The framing — that a premium brand's user trust is the primary risk metric, not just the raw defect count — is a product quality perspective I hold independently and would defend without Claude's involvement.

---

*This document does not include personal identifying information in accordance with the assignment instructions.*
