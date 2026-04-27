# Adaptive Listening Modes — QA Assignment Documentation

**Assignment:** Software QA Technical Assignment — Bang & Olufsen  
**Feature Under Test:** Adaptive Listening Modes (Noise Cancellation / Transparency Mode)  
**Platforms:** iOS and Android  

---

## Overview

This document describes the approach, rationale, and methodology applied to Assignment 1 of the B&O QA technical assessment. The assignment covers a new Adaptive Listening Modes feature for wireless earbuds and their companion mobile application, including manual test strategy, risk analysis, test design, bug reporting, and release recommendation.

A distinguishing characteristic of this submission is the application of **acoustic domain knowledge** throughout the analysis. Rather than treating the earbuds as a software system with a UI layer and a black-box device layer, this submission models the full signal chain — from app UI tap, through BLE GATT write, to DSP pipeline execution, to measurable acoustic output at the ear canal. This perspective surfaces risks and test criteria that a purely software-oriented QA approach would miss.

---

## Methodology

### Approach to Requirements Analysis (Task 1)

Requirements were reviewed against three lenses:

1. **Software/protocol completeness** — Are all states, transitions, and error conditions defined for the BLE control layer?
2. **Acoustic/DSP completeness** — Are the acoustic behaviors fully specified, including switching artifacts, filter convergence, and gain ramping?
3. **User experience and safety** — Are edge cases involving single-earbud use, in-ear detection, and abrupt battery cutoff handled safely from a psychoacoustic perspective?

Key missing requirements identified:
- **DSP pipeline definition per mode** — Hybrid ANC vs feedforward-only; adaptive vs fixed Transparency gain
- **2-second SLA measurement boundary** — UI render vs acoustic change at ear canal (these can differ by 500ms–1.5s)
- **Psychoacoustic safety during switching** — gain ramp duration to suppress click/pop transients
- **Single-earbud occlusion effect** — undefined behavior when one earbud is removed in ANC mode
- **Firmware compatibility negotiation** — no capability handshake defined for legacy firmware
- **NVM write atomicity** — undefined behavior when disconnect interrupts mode persistence

### Test Approach (Task 2)

The test strategy is structured around a core principle: **acoustic state is the source of truth, not UI state.** The app's UI is an optimistic rendering of a cached state — the DSP is the real system under test.

Testing was scoped into three layers:
- **Functional verification** — Happy path and core mode switching with acoustic confirmation
- **State synchronization** — All transitions across the connection lifecycle (connect, background, disconnect, reconnect)
- **Environmental and physical stress** — Real-world acoustic conditions that go beyond lab testing

### Test Case Design (Tasks 3 & 4)

Test scenarios were selected for high failure probability and high user impact, not for coverage breadth. Each scenario maps to a specific failure mode:

| Scenario | Failure Mode Targeted |
|---|---|
| TS-01: Acoustic SLA | DSP latency exceeding spec |
| TS-02: Switching artifact | Gain discontinuity on filter switch |
| TS-03: NVM write race | State revert on rapid disconnect |
| TS-04: Low battery lock | Dangerous mode lock on dying battery |
| TS-05: RF congestion | GATT write timeout in real environments |
| TS-06: HFP call conflict | Mic arbitration deadlock |
| TS-07: Rapid toggling | GATT queue saturation, wrong terminal state |
| TS-08: Single earbud | Occlusion effect and undefined mode behavior |
| TS-09: Firmware mismatch | Silent failure on missing GATT characteristic |
| TS-10: Fuel gauge under DSP load | Battery percentage jump on mode switch |

Detailed test cases (TC-01, TC-02) include:
- Explicit acoustic pass/fail criteria expressed in dB attenuation thresholds
- Defined measurement methodology (reference mic at output port or IEC 711 ear canal simulator)
- Distinct treatment of UI latency vs acoustic latency as separate measured variables

### Bug Report (Task 5)

The observed symptom was decomposed into **two distinct defects** with different root causes:

- **Defect A (8–12s acoustic delay):** Firmware sends ATT_WRITE_RSP before DSP filter coefficient reload completes. App treats ACK as mode-confirmed and renders new state prematurely.
- **Defect B (state mismatch after reconnect):** NVM write is asynchronous and occurs after the BLE ACK. Rapid disconnect (case insertion) interrupts the NVM commit. Firmware boots from previous NVM state; app reads stale local cache. These appear as one symptom but require separate firmware fixes.

### Exploratory Testing (Task 6)

Exploratory scenarios were selected based on acoustic physics and real user behavior:
- ANC convergence window at earbud insertion (feedback filter not yet settled)
- Feedforward mic saturation in wind (Transparency mode)
- Jaw movement / occlusion effect variation during ANC
- Perceived pressure change during rapid mode transitions
- RF-congested environments (2.4GHz saturation)
- Peak transient in audio stream coinciding with mode switch

### Release Recommendation (Task 7)

**Recommendation: No release. Hold for Release Candidate.**

The 1-in-25 reconnect state mismatch (4% failure rate) is a trust-critical defect for a premium audio brand. Combined with the Android 4-second SLA breach (a spec violation), release is not advisable. A conditional release path is defined contingent on: (a) Android latency fix, (b) iOS wording fix, and (c) a server-side kill switch for the feature pending a firmware patch for the NVM write race.

---

## Tools and Environment

| Item | Detail |
|---|---|
| Measurement reference | IEC 711 ear canal simulator or calibrated MEMS reference mic |
| Audio analysis | Spectrogram / RTA at 96kHz capture rate for artifact detection |
| RF environment simulation | Wi-Fi analyzer + multiple APs on overlapping 2.4GHz channels |
| Battery simulation | Debug/engineering firmware mode for simulated battery level injection |
| Platforms | iOS (iPhone 13, iOS 16.5) + Android (Samsung S22, Android 13 + stock Android reference) |

---

## References

### Bluetooth and Protocol
- Bluetooth SIG. (2023). *Bluetooth Core Specification 5.4 — Vol. 3, Part G: Generic Attribute Profile (GATT)*. https://www.bluetooth.com/specifications/specs/core-specification-5-4/
- Bluetooth SIG. (2023). *Assigned Numbers — Battery Service (BAS) Characteristic*. https://www.bluetooth.com/specifications/assigned-numbers/
- Bluetooth SIG. *Advanced Audio Distribution Profile (A2DP) Specification*. https://www.bluetooth.com/specifications/specs/advanced-audio-distribution-profile-1-4/
- Bluetooth SIG. *Hands-Free Profile (HFP) 1.9 Specification*. https://www.bluetooth.com/specifications/specs/hands-free-profile-1-9/

### Acoustic and DSP
- Kates, J. M. (2008). *Digital Hearing Aids*. Plural Publishing. *(Chapter 3: Adaptive Feedback Suppression — relevant to ANC stability during filter transitions)*
- Bai, M. R., & Lee, C. C. (2006). Development and implementation of active noise control system using the DSP-based platform. *Applied Acoustics, 67*(6), 559–571.
- International Electrotechnical Commission. (2010). *IEC 60268-7: Sound System Equipment — Headphones and Earphones* (measurement methodology for earbud acoustic output).
- Zwicker, E., & Fastl, H. (2013). *Psychoacoustics: Facts and Models* (3rd ed.). Springer. *(Chapter 4: Masking — relevant to audibility thresholds for switching transients)*

### iOS and Android Bluetooth Stack
- Apple Developer Documentation. *Core Bluetooth Framework — CBPeripheral and background modes*. https://developer.apple.com/documentation/corebluetooth
- Apple Developer Documentation. *Core Bluetooth Background Execution Modes*. https://developer.apple.com/library/archive/documentation/NetworkingInternetWeb/Conceptual/CoreBluetooth_concepts/CoreBluetoothBackgroundProcessingForIOSApps/PerformingTasksWhileYourAppIsInTheBackground.html
- Android Developer Documentation. *BluetoothGatt — GATT operations and connection priority*. https://developer.android.com/reference/android/bluetooth/BluetoothGatt
- Android Developer Documentation. *Optimize battery for Bluetooth LE*. https://developer.android.com/guide/topics/connectivity/bluetooth/ble-overview#optimizing

### Testing Methodology
- Bath, G. (2012). *Foundations of Software Testing: ISTQB Certification* (3rd ed.). Cengage Learning.
- Kaner, C., Bach, J., & Pettichord, B. (2001). *Lessons Learned in Software Testing*. Wiley. *(Chapter 7: Context-Driven Testing — basis for exploratory test design)*
- IEEE Std 829-2008. *IEEE Standard for Software and System Test Documentation*.
- Copeland, L. (2004). *A Practitioner's Guide to Software Test Design*. Artech House. *(Risk-based test prioritization methodology)*

### Non-Volatile Memory and Firmware
- Angert, P. (2019). *Embedded Systems Design with the Texas Instruments MSP432P401R Microcontroller*. Cengage. *(NVM write atomicity and power-loss resilience patterns)*

---

*This document does not include personal identifying information in accordance with the assignment instructions.* 
