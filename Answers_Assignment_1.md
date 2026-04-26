# Bang & Olufsen — Adaptive Listening Modes · Assignment 1

## Task 1: Requirements review & risk analysis

### Unclear or missing requirements
* **DSP pipeline definition:** The spec says "switch between Noise Cancellation and Transparency" but doesn't define what each mode means acoustically. Does Transparency use a fixed passthrough gain or an adaptive feedforward algorithm? Does ANC run hybrid (FF+FB) or feedforward-only? These distinctions matter because switching paths differ in latency and risk of producing pops or pressure transients at the ear.
* **The 2-second SLA definition:** Is this measured from UI tap → BLE GATT write acknowledge? Or from UI tap → acoustic change at the ear confirmed by the device microphone? These can differ by 500ms–1.5s. The SLA must specify the measurement boundary. For a premium product, the perceptible acoustic change is the only meaningful endpoint.
* **In-ear detection and single-earbud use:** If one earbud is removed, does ANC disable on that side (to prevent the alarming "blocked ear" pressure sensation from a one-sided occlusion effect)? What is the expected mode if only the right bud is in-ear? There is no default defined.
* **Psychoacoustic safety during switching:** Abrupt ANC→Transparency transitions at high gain differentials can cause a momentary pressure pop perceived as a click at the eardrum. Is there a defined crossfade or gain-ramping duration to suppress this artifact? If yes, how long? This is a comfort and potentially a safety-adjacent requirement.
* **Call audio interaction:** During an HFP call, the HFP SCO profile takes control of the microphones. Does the app allow mode switching during a call? If ANC uses the same MEMS mic hardware, what is the priority arbitration — HFP or ANC? Undefined behavior here can degrade call intelligibility.
* **Low-battery behavior continuity:** The 5% threshold blocks mode switching. Does the currently active mode remain locked (user is stuck in whatever mode was last set), or does it fall back to a safe default such as Transparency? Locking ANC active on critically low battery that then abruptly dies creates a sudden acoustic pressure change in the user's ear.
* **Firmware version compatibility matrix:** No compatibility table is defined. If the firmware does not support a GATT characteristic that the app writes, what is the expected error handling? Silent failure is unacceptable. Is there a capability negotiation handshake on connection?

### Top quality risks
* **Critical - Acoustic state vs. UI state desynchronization:** The app operates optimistically — it renders the new mode before receiving a DSP acknowledgement from the firmware. If the BLE write fails silently, or if the DSP rejects the mode command due to a buffer conflict, the user hears one mode but sees another. For ANC this is immediately perceptible. This is the most trust-destroying failure mode for a premium brand.
* **Critical - NVM write race on disconnection:** If the firmware writes the new mode to non-volatile memory asynchronously after sending the BLE ACK (rather than before), a rapid disconnect — such as inserting earbuds into the case — can interrupt the NVM write. The result: the app persists "Transparency" while the NVM reverts to "ANC" on next power-on. This is exactly the failure observed in Task 5.
* **High - 2-second SLA in real RF environments:** The SLA will likely pass in a shielded lab. In a 2.4GHz-congested environment (busy office, train, airport), BLE retransmission can push the GATT write round-trip above 2 seconds. The 2-second SLA is a user experience commitment, not a lab metric — it must be validated in representative environments.
* **High - DSP crossfade and switching artifacts:** Transitioning between ANC and Transparency requires reconfiguring the feedback filter coefficients. Without a defined gain-ramping window, this can produce audible clicks or brief pressure transients. These may be imperceptible on cheap earbuds but are immediately noticeable on high-sensitivity drivers in a premium product.
* **Medium - Platform-specific Bluetooth stack differences:** iOS CoreBluetooth and Android BluetoothGatt differ in how they handle GATT write queuing, connection interval negotiation, and background process suspension. Android's BluetoothGatt can drop pending operations when the connection interval is negotiated down by the peripheral. iOS suspends background BLE writes when the app is backgrounded unless the app holds a peripheral manager session. These are platform bugs, not network bugs.
* **Medium - Battery level reporting accuracy:** Earbud battery levels are typically polled via a BLE Battery Service GATT characteristic. The reported value is a fuel gauge estimate — not a real-time coulomb count. Under high DSP load (ANC active), fuel gauge accuracy degrades. There is a risk that the 5% blocking threshold fires prematurely or too late depending on discharge curve calibration.

---

## Task 2: Test approach

### What I test first and why
Before testing any app behavior, I establish a reliable acoustic ground truth. Using a calibrated measurement microphone (or an IEC 711 ear canal simulator if available) positioned at the earbud output, I confirm the device can switch modes at all and measure the actual DSP transition latency end-to-end. If this baseline is broken, all subsequent UI testing is meaningless. I treat the acoustic change — not the UI update — as the source of truth throughout.

### Highest priority areas
* **State consistency across the full connection lifecycle:** connect, switch mode, background app, foreground, disconnect, reconnect. The synchronization between app-rendered state and actual DSP state is the most premium-critical quality dimension.
* **The 2-second SLA in realistic RF environments:** not just lab conditions. I would test in a space with dense 2.4GHz interference using a Wi-Fi analyzer to confirm channel utilisation above 70%.
* **Acoustic artifact suppression during mode switch:** clicks, transients, gain discontinuities. These are objectively measurable and subjectively obvious on high-quality drivers.

### Exploratory focus
Beyond scripted tests, I explore the acoustic and physical edge cases that no requirements document anticipates: switching modes in high-wind conditions (feedforward Transparency mics clip in wind, creating a harsh roar), switching immediately after inserting earbuds into the ear canal before the ANC convergence algorithm has settled, and switching during a peak in the audio stream where the output level is highest. These are real user behaviors that stress the DSP in ways a connected-standby test cannot replicate.

### Regression areas
* **Core A2DP audio quality:** SNR, THD, frequency response during ANC and Transparency. New DSP feature code can inadvertently alter the signal chain for normal playback.
* **Power consumption:** ANC is the highest power draw state. Any regression in DSP duty cycle or polling rate introduced by the new feature will surface as reduced playback time.
* **Pairing state and multi-device reconnect behavior.**

### iOS vs Android coverage strategy
Core functional parity tests run simultaneously on both platforms. I then run platform-specific suites targeting known behavioral differences: on iOS, aggressive app backgrounding by Springboard and CoreBluetooth's background mode restrictions; on Android, BluetoothGatt callback threading issues, connection interval negotiations per OEM, and the impact of battery optimization on BLE background tasks. I target at least two Android OEMs (Samsung + stock Android) since BluetoothGatt implementations vary meaningfully between them.

---

## Task 3: High-value test scenarios

* **TS-01: End-to-end acoustic SLA measurement.** Verify the acoustic DSP transition (not just UI render) completes within 2 seconds, measured with a reference mic at the output port. Separate UI latency from actual DSP latency. This is the most important single scenario — if the acoustic change doesn't happen, nothing else matters.
* **TS-02: Switching artifact check (click/pop/pressure transient).** Record the acoustic output during ANC→Transparency and Transparency→ANC transitions at 96kHz sample rate. Analyze for transient peaks exceeding the continuous output level by more than 6dB. On premium drivers, even a 5ms gain discontinuity is audible as a click.
* **TS-03: State persistence after NVM write stress.** Switch mode then immediately (within 200ms) insert earbuds into the case, forcing a disconnect during potential NVM commit window. On reconnect, confirm both app state and acoustic state match the intended mode. Directly targets the race condition that produces the bug in Task 5.
* **TS-04: Low battery DSP lock safety audit.** At battery <5%, confirm the currently active mode is not ANC (which draws more current and could accelerate cell collapse). Verify the UI is locked and the user is not silently left in ANC on a dying battery. Verify the warning message is specific enough for a user to take action.
* **TS-05: RF-congested environment SLA test.** Replicate a busy 2.4GHz environment (set up 3+ Wi-Fi APs on overlapping channels + several BT devices). Measure p95 mode-switch latency across 30 samples. The p95 — not the average — must meet 2 seconds. Average latency in a congested environment can look fine while 1 in 20 taps breaches SLA.
* **TS-06: ANC-to-Transparency during active phone call (HFP/SCO).** Switch listening mode while an HFP SCO call is active. The mic arbitration between HFP and the Transparency feedforward path is undefined. This could degrade call intelligibility for both parties, produce feedback, or cause a firmware crash due to simultaneous mic access.
* **TS-07: Rapid sequential toggling (10+ switches, <500ms interval).** Queue multiple BLE GATT writes faster than the DSP can process them. Confirm the firmware drains the queue in order, does not get stuck in an intermediate state, and that the final acoustic state matches the final UI state. A common failure is the command queue saturating and the firmware settling on the wrong terminal state.
* **TS-08: Single earbud in-ear mode switch behavior.** Remove one earbud while in ANC. The remaining bud runs ANC on one side, creating a strong occlusion effect compared to the open ear — a real comfort and safety concern for premium users. Verify the expected behavior (passthrough fallback or mode lock) is consistent and documented.
* **TS-09: Firmware version mismatch — legacy firmware capability negotiation.** Connect earbuds running a firmware version predating the feature. Verify the app detects the missing GATT characteristic on capability interrogation and presents a graceful degraded state — not a silent failure where the user taps the toggle 5 times wondering why nothing happens.
* **TS-10: Battery level accuracy under DSP load differential.** ANC draws significantly more power than Transparency. Switch between modes mid-playback and monitor the battery percentage reported by the app. Verify the fuel gauge doesn't produce a visible jump (e.g., 42% → 38%) when switching modes, which would alarm users and indicate a poorly calibrated discharge curve.

---

## Task 4: Detailed test cases

### TC-01: Acoustic DSP transition latency — ANC→Transparency within 2s SLA
* **Priority:** P1 — Blocker if failed
* **Platforms:** iOS + Android (execute independently)
* **Preconditions:** Earbuds connected, battery >30%, current mode is Noise Cancellation confirmed acoustically. Reference measurement mic placed at earbud output or in ear canal simulator. Audio analyzer running (e.g., RTA or spectrogram capture). Ambient environment: <45dB SPL background noise, no active Wi-Fi saturation on 2.4GHz channel in use.

**Steps:**
1. Confirm ANC is active acoustically: play pink noise from phone at 70dB SPL from 30cm. Measured output at ear canal should be attenuated by ≥15dB in 100–1000Hz range (confirming ANC DSP is processing). Note timestamp T0.
2. Tap "Transparency Mode" in the app. Note the exact wall-clock time of the UI tap as `T_tap`.
3. Monitor the acoustic output continuously. Note the timestamp when the measured attenuation drops below 5dB (indicating Transparency passthrough is active) as `T_acoustic`.
4. Note the timestamp when the app UI renders "Transparency Mode" as active as `T_ui`.
5. Inspect the recording for transient peaks during the transition window (`T_tap` → `T_acoustic`). Flag any peak exceeding +6dBFS above the continuous output level.
6. Repeat steps 1–5 for Transparency→ANC direction.
7. Repeat the full test 5 times per direction per platform. Record all latency samples.

* **Pass criteria:** (`T_acoustic` − `T_tap`) ≤ 2000ms on all 5 samples, both directions, both platforms. No transient peak exceeding +6dBFS during transition. `T_ui` may precede or follow `T_acoustic` — this delta is reported separately as "optimistic rendering offset" and does not independently cause a fail, but a `T_ui` < `T_acoustic` gap >500ms is flagged for investigation.
* **Fail criteria:** Any single sample exceeds 2000ms acoustic latency. Any audible transient artifact confirmed by recording analysis. Acoustic state and UI state differ at test end.

### TC-02: Mode state persistence across rapid disconnect — NVM write race validation
* **Priority:** P1 — Blocker if failed
* **Platforms:** iOS + Android
* **Preconditions:** Earbuds connected, battery 30–80%, current mode is Noise Cancellation (confirmed acoustically and in UI). Charging case available. Stopwatch ready for timing.

**Steps:**
1. Tap "Transparency Mode" in the app UI. Note `T_tap`.
2. Immediately (within 200ms of `T_tap`, before acoustic confirmation) insert both earbuds into the charging case and close the lid. This deliberately interrupts the potential NVM write window.
3. Wait 15 seconds. Confirm the app shows the device as disconnected.
4. Open the case lid and remove both earbuds. Wait for reconnection (up to 10 seconds).
5. Read the UI-displayed mode. Record as `UI_reported_mode`.
6. Acoustically verify the active mode: play pink noise from 30cm, measure attenuation at ear output. >15dB attenuation in 100–1000Hz = ANC. <5dB attenuation = Transparency. Record as `Acoustic_mode`.
7. Repeat test 5 times, alternating between ANC→Transparency and Transparency→ANC initial transitions.

* **Pass criteria:** `UI_reported_mode` and `Acoustic_mode` are identical on all 5 repetitions. The persisted mode may be either ANC or Transparency (firmware may legitimately revert to the pre-switch state if the write was interrupted) — the critical requirement is that UI and acoustic state match, not which mode is selected.
* **Fail criteria:** `UI_reported_mode` ≠ `Acoustic_mode` on any repetition. This constitutes a state desynchronization defect regardless of which mode each layer reports.

---

## Task 5: Bug report

**Title:** Acoustic/UI state desynchronization: DSP remains in ANC 8–12s after Transparency selected; NVM revert on reconnect causes permanent mismatch
* **Severity:** Critical
* **Component:** Firmware / BLE Control
* **Priority:** P0 — Blocker

**Description:**
Two distinct but likely related defects are present. 
* **Defect A:** The BLE GATT write for mode change is acknowledged by the firmware before the DSP has committed the new filter configuration, causing the app to render the new mode while the earbuds are still running the old DSP pipeline (ANC remains active 8–12 seconds after Transparency is selected). 
* **Defect B:** When the earbuds are placed in the case within the NVM write window, the mode change is not persisted to non-volatile memory. On reconnect, the firmware boots from the last NVM-persisted state (ANC) while the app reads from its local cache (Transparency), producing a permanent mismatch until the user explicitly switches modes again.

**Steps to reproduce:**
1. Connect earbuds. Confirm Noise Cancellation is active acoustically (significant attenuation of ambient sound).
2. Tap "Transparency Mode" in the companion app. App UI immediately shows Transparency as active.
3. Listen acoustically. Earbuds continue attenuating ambient sound in ANC for 8–12 seconds before Transparency activates. *(Defect A)*
4. Within 500ms of tapping Transparency, insert earbuds into case and close lid.
5. Remove earbuds after 15 seconds. Reconnect.
6. App shows Transparency; earbuds are acoustically in ANC. State mismatch persists until user manually switches modes. *(Defect B)*

**Expected vs. Actual:**
* **Expected (Defect A):** Acoustic DSP transition to Transparency within ≤2 seconds of UI tap.
* **Actual (Defect A):** DSP remains in ANC 8–12 seconds. App renders state change before firmware DSP commit.
* **Expected (Defect B):** Mode persists to NVM before BLE ACK is sent. On reconnect, acoustic and app state match.
* **Actual (Defect B):** NVM write occurs after BLE ACK. Rapid disconnect interrupts the write. Firmware reverts to previous NVM state on boot. UI reads stale app-side cache.

**Environment:**
* App: v2.1.0-beta
* Firmware: FW_1.4.2
* iPhone 13 (iOS 16.5) / Samsung S22 (Android 13)
* Reproduced on both platforms.

**Root cause hypothesis:**
* **Defect A:** The firmware sends a GATT write response (`ATT_WRITE_RSP`) immediately upon receiving the command, before the DSP has completed the filter coefficient reload and gain-ramping sequence. The app treats `ATT_WRITE_RSP` as mode-confirmed and updates UI. Fix: firmware should only send `ATT_WRITE_RSP` after the DSP confirms the new pipeline is active, or use a separate notification characteristic to signal acoustic confirmation. 
* **Defect B:** The NVM write is queued after the BLE ACK rather than completed synchronously. The persistent state store should be updated as part of the mode-apply transaction, before the ACK. Alternatively, the app should read the actual device GATT state on reconnect rather than using a local cache.

---

## Task 6: Exploratory testing — real-world acoustic situations

Scripted tests validate defined requirements. Exploratory testing finds failures that were never specified because no one anticipated the physical context. For earbuds, that means leaving the lab.

### Physical and acoustic scenarios
* **ANC convergence before switching:** Insert earbuds and switch to Transparency within the first 500ms, before the ANC algorithm has converged on the ear canal's acoustic impedance. The feedback path is still adapting. This can cause a brief howl or instability. Switch back immediately and test whether the DSP recovers cleanly.
* **Wind noise in Transparency:** Run Transparency mode while standing in wind (or with a desk fan aimed at the earbuds). The feedforward microphones in Transparency mode are exposed to airflow, which saturates the mic capsule and produces a harsh roaring artifact. This is an expected acoustic limitation, but the question is whether switching to ANC in this state is fast and clean, and whether the app should warn the user.
* **Jaw movement and chewing:** Premium earbud drivers are susceptible to occlusion effect changes caused by jaw movement, which alters the ear canal volume. Switch modes while eating. The ANC feedback filter may momentarily oscillate as the physical acoustic load changes dynamically. This is an unscripted but very common real-world behavior.
* **Pressure equalization during mode switch:** On earbuds with deep insertion, switching from ANC to Transparency can cause a sudden perceived pressure change in the ear canal (similar to an altitude equalization sensation). This is psychoacoustically unpleasant. Exploratory: switch modes in a quiet environment and subjectively rate comfort. If the sensation is noticeable, the gain ramp-down duration in the firmware is likely too short.
* **RF saturation at mass transit hubs:** Test mode switching at a busy train station or airport. BLE operates in the same 2.4GHz band as hundreds of concurrent devices. Measure whether the GATT write times out and whether the app handles the timeout gracefully (retry vs. silent failure vs. error message).
* **Abrupt audio playback content during mode switch:** Switch modes at the exact moment of a loud transient in the audio stream (kick drum, clap). The combined DSP filter reconfiguration + high instantaneous output level is the worst case for switching artifacts. Record and analyze.

---

## Task 7: Release recommendation

### Recommendation: No release — hold for Release Candidate

**Issue 1 — Android 4s latency (SLA breach)**
The 2-second requirement is a published product specification. A 4-second acoustic response is objectively measurable by users and reviewers alike. For a premium audio brand, this will appear in day-one reviews as a responsiveness failure. **Severity: High.** A targeted BLE connection interval negotiation fix is likely low-risk and can be turned around in one sprint.

**Issue 2 — iOS battery-low wording**
Confusing wording on a safety-adjacent feature (the user cannot change modes and may not understand why) is not cosmetic — it is a usability defect. However, it is a string change, not a code change. This alone would not block release; it would be fixed via an app store update within days. **Severity: Medium on its own.**

**Issue 3 — Reconnect state mismatch, 1-in-25 rate (4%)**
This is the blocking issue. A 4% failure rate means that roughly 1 in every 6 users who reconnect their earbuds three or more times per day will encounter a mismatch. The user hears one acoustic environment but the app reports another. At the premium price point B&O commands, users will interpret this as a defect and contact support or return the product. This is the same NVM write race described in Task 5 and has a defined fix path: synchronize the NVM write before sending the BLE ACK, and read device state on reconnect rather than relying on cached state. **Severity: Critical.**

### Conditional release path (if timeline is critical)
If a hard ship deadline exists, a conditional release is possible only if: 
(a) the Android latency is fixed — this is a spec violation and non-negotiable; 
(b) the iOS wording is fixed in the same build; and 
(c) a server-side kill switch is available to disable the Adaptive Listening Modes feature entirely if the reconnect mismatch rate in production telemetry exceeds 2%, buying time for a firmware patch. Without a kill switch, a conditional release with a known 4% state mismatch rate is not appropriate for this brand.
