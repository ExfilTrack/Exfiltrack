# Organizational Prerequisites

**Owner:** All members
**Tracking issue:** _to open_ — suggested title: "Document pre-incident endpoint configuration prerequisites"

Endpoint configuration that must be in place **before** an incident for ExfilTrack to have anything to analyse.

**This file is a companion to [limitations.md](limitations.md).** That file states what ExfilTrack cannot prove. This file states what must already be true of the endpoint for ExfilTrack to prove anything at all.

---

## Why This File Exists

`limitations.md` records the boundary between forensic tooling and organizational policy, and lists three Category 1 prerequisites: mobile-sync restriction, removable-storage class blocking, and centralized log forwarding.

All three are channel-blocking controls. They stop an exfiltration path. But there is a second, equally important reason to configure an endpoint in advance, and the current documentation does not cover it:

> Several of the artifacts ExfilTrack's V1 parsers read do not exist by default, or can be erased by the employee — in some cases **without administrator rights**.

This is not a defect in any parser. It is a property of the artifacts themselves, and it belongs in Category 1 alongside the channel-blocking controls.

The practical consequence is a silent failure mode. ExfilTrack does not crash when an artifact was never created or has been wiped. It runs normally, finds nothing, and produces a clean report. An investigator reading that report cannot distinguish "no exfiltration occurred" from "the evidence was never generated" unless the tool says which sources were absent — see [Reporting Requirement](#reporting-requirement) below.

---

## Part 1 — What V1 Actually Depends On

Scoped to the four parsers that exist in `src/exfiltrack/parsers/` today. Planned parsers are in [Part 4](#part-4--prerequisites-for-planned-parsers).

| V1 evidence | Parser | How it is lost | Admin needed? | Required control |
|---|---|---|---|---|
| `SYSTEM\<ControlSet>\Enum\USBSTOR` | `registry_parser` | USB history cleaners (USBOblivion, USBDeview) delete the device subkeys | **Yes** | [A1](#a1) admin removal · [C7](#c7) application allowlisting |
| `SYSTEM\MountedDevices` | `registry_parser` | Same tooling; also naturally sparse | **Yes** | [A1](#a1) · [C7](#c7) |
| `SOFTWARE\...\Windows Portable Devices\Devices` | `registry_parser` | Same tooling | **Yes** | [A1](#a1) · [C7](#c7) |
| `NTUSER.DAT\...\Explorer\MountPoints2` | `registry_parser` | **The user can delete their own subkeys.** This is their own hive. | **No** | [C5](#c5) shadow copies · [D3](#d3) SACL on the key |
| DriverFrameworks-UserMode 2003 / 2100 / 2102 | `evtx_parser` | **Channel is disabled by default on Windows 10/11 — produces nothing at all**; also log clearing and wrap-around | n/a (never enabled) | [D5](#d5) enable channel · [C1](#c1) revoke clear right · [C2](#c2) SIEM · [C3](#c3) log size |
| Kernel-PnP 20001 / 20003 | `evtx_parser` | Log clearing; wrap-around | **Yes** to clear | [C1](#c1) · [C2](#c2) · [C3](#c3) |
| Security 4663 `ObjectType=File` | `evtx_parser` | **Requires Object Access auditing plus a SACL — absent by default, produces nothing** | n/a (never enabled) | [D3](#d3) audit policy + SACLs |
| `.lnk` files in `Recent\` | `lnk_parser` | **User deletes the folder, or sets `NoRecentDocsHistory` — neither needs elevation** | **No** | [C6](#c6) enforce tracking ON · [C5](#c5) shadow copies |
| Jump Lists | `jumplist_parser` | **User deletes `AutomaticDestinations`, or turns off `Start_TrackDocs` — no elevation** | **No** | [C6](#c6) · [C5](#c5) |
| **The entire evidence set** | all | Employee boots a Linux live USB, or removes the SSD and mounts it externally. No Windows artifacts are generated at all. | **No** — physical access only | [A2](#a2) BitLocker TPM+PIN · [A3](#a3) UEFI password, Secure Boot, USB boot disabled |

### The finding that matters most

Four of the ten rows above are marked **"Admin needed? No."** Together they cover the `.lnk` parser, the Jump List parser, and the per-user attribution half of the registry parser — that is **two and a half of ExfilTrack's four V1 parsers, defeated by a standard user with no elevation whatsoever.**

Removing local administrator rights, which is the single strongest control against most anti-forensic activity, does **not** address these. The `Recent` folder and `MountPoints2` live inside the user's own profile and hive; the user owns them.

Only three things help:

1. **[C6](#c6) — enforce recent-items and Jump List tracking ON and lock the setting.** Prevents suppression. Does not prevent deletion.
2. **[C5](#c5) — Volume Shadow Copies.** The only mechanism that recovers a `Recent` folder or `NTUSER.DAT` the user deleted yesterday. This is the highest-value control for V1 and it costs nothing but disk space.
3. **[D3](#d3) — a SACL on the `Recent` folder and the `MountPoints2` key.** Turns the deletion itself into a logged 4663 event forwarded off the box. The deletion becomes evidence.

Shadow copies deserve emphasis: they are what convert a user-deletable artifact into a durable one, and V1's exposure to unelevated deletion is the strongest argument for the planned VSS ingestion module.

---

## Part 2 — Controls

Grouped by purpose. Each entry gives where to apply it, how to verify, and an honest assessment of developer impact — a control that gets rolled back after complaints is not a control.

Priorities: **P0** blocks the whole tool · **P1** disables a specific V1 parser · **P2** closes an additional channel.

### Group A — Privilege and Boot Integrity

<a id="a1"></a>
#### A1. Remove standing local administrator rights `P0`

- **Where:** Remove users from local `Administrators` via GPO Restricted Groups or Intune. Provide time-boxed elevation through LAPS or a PAM tool with logged justification.
- **Verify:** `net localgroup Administrators`
- **Dev impact:** *Low.* IDEs, containers, package managers, and local builds do not need elevation. Expect requests in the first two weeks for driver installs and low-port binding — route them through the JIT process rather than reverting.
- **Protects:** every registry-based V1 artifact, and every event log.

<a id="a2"></a>
#### A2. BitLocker full-disk encryption with pre-boot authentication `P0`

- **Where:** `Computer Configuration\Administrative Templates\Windows Components\BitLocker Drive Encryption\Operating System Drives` → *Require additional authentication at startup* (TPM + PIN). Escrow recovery keys to AD / Entra ID.
- **Verify:** `manage-bde -status C:` → `Protection On`, TPM+PIN protector present.
- **Dev impact:** *Very low.* One PIN at boot. Hardware AES makes the compilation cost negligible.

<a id="a3"></a>
#### A3. UEFI supervisor password, Secure Boot, boot order lockdown `P0`

- **Where:** Firmware config via vendor tooling (Dell Command, HP CMSL, Lenovo Commercial Vantage). Disable USB and network boot. Enable Secure Boot and Kernel DMA Protection.
- **Verify:** `Confirm-SecureBootUEFI`; `msinfo32` → *Kernel DMA Protection*.
- **Dev impact:** *None*, unless engineers legitimately dual-boot Linux — provision a supported dual-boot image rather than leaving firmware open.

A2 and A3 are one control in two parts. Either alone is insufficient: encryption without a locked boot order still allows a live-USB boot that sees an encrypted volume but generates no Windows artifacts, and a locked boot order without encryption is defeated by removing the drive.

#### A4. Deny system time modification `P2`

- **Where:** User Rights Assignment → *Change the system time*, remove `Users`. Enforce domain NTP. Audit Event ID **4616**.
- **Why:** every V1 correlation rule is a time comparison. `sessions.py` and `scoring.py` both assume a monotonic, accurate clock.
- **Dev impact:** *None.* Time manipulation for testing belongs inside containers.

### Group B — Removable Media and Peripheral Channels

#### B1. Restrict removable storage across all device classes `P1`

- **Where:** `Computer Configuration\Administrative Templates\System\Removable Storage Access`. Apply *Deny write access* to **Removable Disks**, **WPD Devices**, **CD and DVD**, **Floppy**, and **Tape** — not USB alone.
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\RemovableStorageDevices\{class-GUID}\Deny_Write = 1`
- **Class GUIDs:** Removable Disks `{53f5630d-b6bf-11d0-94f2-00a0c91efb8b}` · CD/DVD `{53f56308-b6bf-11d0-94f2-00a0c91efb8b}` · WPD `{6AC27878-A6FA-4155-BA85-F98F491D4F33}`, `{F33FDC04-D1AC-4E8E-9A30-19BBD4B108AE}`
- **Note:** `limitations.md` already lists removable-storage class blocking. This entry only widens it beyond USB.

#### B2. Hardware whitelisting by VID/PID `P2`

- **Where:** `…\System\Device Installation\Device Installation Restrictions` → *Allow installation of devices that match any of these device IDs*, plus *Prevent installation of devices not described by other policy settings*.
- **Dev impact:** *Low.* Needs an approved-device catalogue and a request process.

#### B3. BitLocker To Go enforcement `P1`

- **Where:** `…\BitLocker Drive Encryption\Removable Data Drives` → *Deny write access to removable drives not protected by BitLocker*.
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\FVE\RDVDenyWriteAccess = 1`
- **Why this matters for the scoring model:** `Confirmed` is reachable only through `DESTINATION_HASH_MATCH` — a hash match against a file on the destination device. That requires the destination device to be recoverable *and readable*. If writes are only permitted to BitLocker-encrypted drives with organization-escrowed recovery keys, a recovered drive can be decrypted and imaged. Without this control, `Confirmed` is unreachable in practice for any employee who encrypts their own drive.
- **Dev impact:** *None* for the common case; encryption is transparent once applied.

#### B4. Block Bluetooth file transfer and Wi-Fi Direct `P2`

- **Where:** Device Installation Restrictions by setup class — Bluetooth `{e0cbf06c-cd8b-4647-bb8a-263b43f0f974}` — or MDM `Bluetooth/AllowDiscoverableMode` and `Bluetooth/AllowPrepairing`. Block hotspot and tethering profiles.
- **Why:** an OBEX transfer produces **no `USBSTOR` artifact of any kind**. ExfilTrack is blind to it by design, and nothing in the current documentation names this channel.
- **Dev impact:** *None.* HID peripherals and audio still pair; only file transfer is removed.

#### B5. Enable print auditing `P2`

- **Where:** `wevtutil sl Microsoft-Windows-PrintService/Operational /e:true`. Event ID **307** records user, document name, page count, byte size.
- **Dev impact:** *None.* Printing is unchanged; only the audit record is added.

### Group C — Evidence Preservation

<a id="c1"></a>
#### C1. Revoke the right to clear security logs `P0`

- **Where:** User Rights Assignment → *Manage auditing and security log* (`SeSecurityPrivilege`), administrators only.
- **Verify:** `wevtutil cl Security` as a standard user must fail with access denied.

<a id="c2"></a>
#### C2. Real-time log forwarding to a SIEM `P0`

- **Where:** Windows Event Forwarding or an EDR/SIEM agent. Minimum channels: Security, System, **DriverFrameworks-UserMode/Operational**, Kernel-PnP/Configuration.
- **Why:** `limitations.md` already lists centralized log forwarding. Worth making explicit that the DriverFrameworks channel — the source of V1's `usb_insert` and `usb_remove` session boundaries — must be in the forwarding set, or the highest-value V1 evidence stays only on the endpoint.

<a id="c3"></a>
#### C3. Raise local event log sizes `P1`

- **Where:** `…\Event Log Service\{Security|System}` → *Specify the maximum log file size (KB)*
- **Registry:** `HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Security\MaxSize`
- **Suggested:** Security ≥ 1 GB, System ≥ 256 MB. Defaults wrap within days on a busy developer machine, which silently removes older sessions from `sessions.py` reconstruction.
- **Verify:** `wevtutil gl Security` → check `maxSize`.

<a id="c5"></a>
#### C5. Volume Shadow Copies enabled, sized, and retained `P1` — **highest value for V1**

- **Where:** `vssadmin resize shadowstorage /for=C: /on=C: /maxsize=15%`, plus a scheduled task creating daily snapshots.
- **Why:** the only control that recovers artifacts a **standard user** deleted — the `Recent` folder, Jump Lists, and `MountPoints2` subkeys. Nothing in Group A helps with those, because the user owns them.
- **Verify:** `vssadmin list shadows`
- **Also:** alert on `vssadmin delete shadows` and `Delete-CimInstance Win32_ShadowCopy`.
- **Dev impact:** *Positive.* Developers gain free local rollback.

<a id="c6"></a>
#### C6. Keep Explorer recent-items and Jump List tracking ON `P1`

- **Where:** `User Configuration\Administrative Templates\Start Menu and Taskbar` → *Do not keep history of recently opened documents* must be **Disabled or Not Configured**; *Clear history of recently opened documents on exit* must be **Disabled**.
- **Registry:** `HKCU\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\NoRecentDocsHistory = 0`, `ClearRecentDocsOnExit = 0`, and `…\Explorer\Advanced\Start_TrackDocs = 1`
- **Why:** these are HKCU values. A standard user can set them, and both the `lnk_parser` and `jumplist_parser` then have nothing to read — permanently and silently. Enforce through GPO so the user-side value is overridden.
- **Dev impact:** *None.* This is default Windows behaviour and a convenience feature developers use.

<a id="c7"></a>
#### C7. Application allowlisting `P1`

- **Where:** WDAC (preferred) or AppLocker. Publisher-based allowlist for development toolchains. Block execution from `%TEMP%`, `%USERPROFILE%\Downloads`, and removable media.
- **Why:** blocks the purpose-built utilities — USBOblivion, USBDeview, CCleaner, BleachBit — that exist specifically to erase the registry keys the `registry_parser` reads.
- **Dev impact:** *Medium — the highest-friction item here.* Deploy in audit mode for 4–6 weeks first, build the publisher allowlist from real telemetry, keep a fast exception path. Rolling this out without an audit phase will generate legitimate complaints.

### Group D — Evidence Generation

*These artifacts do not exist on a stock Windows 11 machine. Not enabling them means there is nothing to recover — not later, not ever.*

<a id="d3"></a>
#### D3. Object access auditing with SACLs `P1`

- **Where:** Advanced Audit Policy → *Object Access* → *Audit File System* (Success). Then apply SACLs to:
  - protected project directories — the source of `file_access` events
  - `%APPDATA%\Microsoft\Windows\Recent` — so **deletion of the LNK evidence is itself logged**
  - the `MountPoints2` key — same reasoning, via *Audit Registry*
- **Why:** `evidence-sources.md` already notes that 4663 exists only when audit policy and a SACL are in place. This entry says which paths to SACL, and adds the anti-forensic use: SACLing the evidence locations turns unelevated deletion into a forwarded event.
- **Dev impact:** *Low if scoped correctly.* SACL a bounded set of paths — **not** build output or `node_modules`, which floods the log and slows I/O. This targeted scoping is the alternative to the real-time DLP scanning that freezes IDEs.

#### D4. Removable storage auditing `P1`

- **Where:** Advanced Audit Policy → *Object Access* → *Audit Removable Storage* (Success and Failure).
- **Dev impact:** *None.* Fires only when removable media is used.

<a id="d5"></a>
#### D5. Enable the DriverFrameworks-UserMode operational channel `P0` — **do this first**

- **Where:** `wevtutil sl Microsoft-Windows-DriverFrameworks-UserMode/Operational /e:true`
- **Why:** events 2003, 2100, and 2102 are V1's **only** session boundaries in `sessions.py`. The channel is **off by default** on Windows 10/11. `limitations.md` already notes this, but notes it as an interpretive caveat rather than as an action the organization must take beforehand — which is what it is.
- **Verify:** `wevtutil gl Microsoft-Windows-DriverFrameworks-UserMode/Operational` → `enabled: true`
- **Dev impact:** *None.* Low-volume channel.

#### D6. EDR tamper protection `P0`

- **Where:** enable tamper protection in the EDR console; deny service-stop rights on security agents.
- **Dev impact:** *None.* No engineering task requires terminating kernel security telemetry.

### Group E — Offboarding

#### E1. Forensic imaging at device return `P0`

- **Process:** when a laptop is returned, take a full write-blocked image **before** re-imaging for reuse. Retain per legal guidance.
- **Why:** this is the procedural control that makes an ExfilTrack investigation possible at all. Every technical control above is worthless if the disk is wiped for the next hire.
- **Note:** `user-guide.md` § *Preparing Evidence* is currently a placeholder. This is the upstream step that produces the `evidence/` directory that section describes.

#### E2. Elevated monitoring during notice periods `P1`

- **Process:** on notice, extend log retention and raise alerting sensitivity for that user. Disclose in the acceptable use policy in advance.

#### E3. Chain-of-custody documentation `P0`

- **Process:** record who imaged the device, when, with which tool, and the SHA-256 of the image. Store alongside the evidence set.
- **Why:** `evidence/hashing.py` and `manifest.py` prove *ExfilTrack* changed nothing. Provenance before ingestion is a human process the tool cannot attest to.

---

## Part 3 — Rollout Sequence

Deploying all of this at once will generate resistance. Suggested phasing:

| Phase | Weeks | Contents | Notes |
|---|---|---|---|
| **1 — Silent** | 1–2 | D5, D3, D4, C3, C5, C6, E1 | **Zero user-visible change.** Pure gain, no exception requests. Do this first regardless of anything else — it is where the effort-to-value ratio is best. |
| **2 — Foundational** | 3–6 | A1, A2, A3, C1, C2, D6 | Expect elevation requests. Staff the JIT process before starting. |
| **3 — Channel** | 7–10 | B1–B5 | Publish the approved-peripheral catalogue before enforcing. |
| **4 — Allowlisting** | 11+ | C7 | Audit mode for 4–6 weeks first. |

Phase 1 alone resolves every "produces nothing at all" row in Part 1.

---

## Part 4 — Prerequisites for Planned Parsers

Not yet applicable — the modules below are not in `src/exfiltrack/parsers/`. Recorded here so the dependency is known before the work starts, since two of these parsers are trivially defeated on an unhardened endpoint and that should inform whether they are worth building first.

| Planned parser | Additional prerequisite | Defeated by | Admin needed? |
|---|---|---|---|
| `$UsnJrnl` / `$MFT` | Pre-size the journal: `fsutil usn createjournal m=2147483648 a=134217728 C:`. Alert on `fsutil usn`. Default journal wraps within days under build load. | `fsutil usn deletejournal /d C:` | Yes |
| PowerShell history | Do not depend on `ConsoleHost_history.txt`. Use script block logging (4104) as the durable substitute; remove the PSv2 engine, which bypasses 4104. | `Set-PSReadLineOption -HistorySaveStyle SaveNothing` | **No** |
| ShellBags (`USRCLASS.DAT`) | C7 allowlisting against privacy cleaners; C5 shadow copies | CCleaner-class wipe; user owns the hive | **No** |
| SRUM (`SRUDB.dat`) | E1 endpoint capture — SRUM is destroyed on re-image | Device re-imaged before analysis | n/a |
| Prefetch | Enforce `HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Memory Management\PrefetchParameters\EnablePrefetcher = 3` via GPO | `EnablePrefetcher = 0` | Yes |
| Shadow Copy ingestion | C5 — VSS enabled, sized, and retained | `vssadmin delete shadows /all` | Yes |

Note the pattern: the two parsers requiring **no elevation** to defeat are the PowerShell history parser and the ShellBags parser. Both read files the user owns. Neither should be built without C5 shadow copies in place, or the module will work correctly in testing and fail against any employee who deletes their own profile data.

---

## Part 5 — Reporting Requirement

<a id="reporting-requirement"></a>

This is an implementation consequence of the above, not an organizational control, and it belongs in the reporting layer.

Because absent evidence and absent activity look identical in the output, every report must include an **Evidence Coverage** section listing which expected sources were present, absent, or empty. Suggested shape:

```
Evidence coverage
  registry/SYSTEM              present    142 events
  registry/NTUSER.DAT          present      8 events
  evtx/DriverFrameworks        ABSENT     channel disabled or not exported
  evtx/Security.evtx           present      0 file_access events
                                          (object-access auditing may not be configured)
  lnk/                         present     37 shortcuts
  jumplists/                   ABSENT     directory not supplied
```

Without this, a report from an unhardened endpoint reads as an exoneration. With it, the investigator can see that the question was never actually asked.

Two related additions worth tracking as separate issues:

- **Coverage flag on findings.** A session scored only from registry evidence, with no DriverFrameworks channel available, should be visibly marked as scored on partial coverage.
- **Confidence ceiling under partial coverage.** Worth discussing whether `evaluate_confidence` should cap at Medium when session boundaries were inferred without DriverFrameworks events. The scoring model already resists overstatement; this extends the same principle to evidence availability.

---

## Part 6 — Verification Script

Run as administrator on a configured endpoint. Read-only; changes nothing.

```powershell
# ExfilTrack pre-incident configuration check (read-only)
$r = [ordered]@{}

$r['LocalAdmins']      = (Get-LocalGroupMember Administrators -EA SilentlyContinue).Name -join '; '
$r['BitLockerOS']      = (Get-BitLockerVolume -MountPoint C: -EA SilentlyContinue).ProtectionStatus
$r['SecureBoot']       = try { Confirm-SecureBootUEFI } catch { 'N/A' }
$r['RDVDenyWrite']     = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\FVE' -Name RDVDenyWriteAccess -EA SilentlyContinue).RDVDenyWriteAccess
$r['DriverFrameworks'] = (wevtutil gl Microsoft-Windows-DriverFrameworks-UserMode/Operational 2>$null | Select-String 'enabled:') -replace '\s+',' '
$r['SecurityLogMaxKB'] = [int](((wevtutil gl Security | Select-String 'maxSize') -replace '\D','')) / 1KB
$r['NoRecentDocs']     = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer' -Name NoRecentDocsHistory -EA SilentlyContinue).NoRecentDocsHistory
$r['TrackDocs']        = (Get-ItemProperty 'HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced' -Name Start_TrackDocs -EA SilentlyContinue).Start_TrackDocs
$r['ShadowCopies']     = (vssadmin list shadows 2>$null | Select-String 'contained').Count
$r['ObjectAccess']     = (auditpol /get /subcategory:"File System" 2>$null | Select-String 'File System') -replace '\s+',' '
$r['RemovableAudit']   = (auditpol /get /subcategory:"Removable Storage" 2>$null | Select-String 'Removable') -replace '\s+',' '

$r.GetEnumerator() | ForEach-Object { '{0,-18} : {1}' -f $_.Key, $_.Value }
```

**Expected on a correctly configured endpoint:**

| Check | Expected | Blocks |
|---|---|---|
| `LocalAdmins` | no standard user accounts | registry parser |
| `BitLockerOS` | `On` | everything |
| `SecureBoot` | `True` | everything |
| `RDVDenyWrite` | `1` | `Confirmed` confidence |
| `DriverFrameworks` | `enabled: true` | session reconstruction |
| `SecurityLogMaxKB` | ≥ 1048576 | older sessions |
| `NoRecentDocs` | `0` or absent | lnk + jumplist parsers |
| `TrackDocs` | `1` | lnk + jumplist parsers |
| `ShadowCopies` | ≥ 1 | recovery of user-deleted artifacts |
| `ObjectAccess` | `Success` | `file_access` events |
| `RemovableAudit` | `Success and Failure` | removable-media access events |

---

## Part 7 — Use in the Test Matrix

The proposal's evaluation plan describes four controlled scenarios. Running each on **two** VM configurations turns this document into a measurable result rather than an assertion:

| VM | Configuration |
|---|---|
| **Baseline** | Stock Windows 11, default settings, user is local administrator |
| **Hardened** | Phase 1 + Phase 2 from [Part 3](#part-3--rollout-sequence) applied |

Run all four scenarios on both. Report, per scenario: events parsed per source, sessions reconstructed, score, confidence level reached, and which sources were absent.

The baseline VM should show a measurable and predictable capability loss — most visibly, zero `usb_insert` and `usb_remove` events, since the DriverFrameworks channel is off by default, meaning no session boundaries and therefore no correlation at all. A fifth scenario is worth adding: **anti-forensic cleanup** — run the theft scenario, then delete the `Recent` folder and `MountPoints2` subkeys as a standard user, and confirm the hardened VM still recovers the evidence from shadow copies while the baseline VM does not.

That comparison is a genuine evaluation result and a stronger contribution than the scoring model alone.

---

## Governance

These controls process employee activity data. Before deployment: an acceptable use policy disclosing endpoint logging and possible forensic analysis; a defined incident-response process naming who may authorise an investigation; role-based access to reports; and legal review. In Malaysia this engages the PDPA; cross-border operation should also account for GDPR and equivalent regimes.

Consistent with the ethical boundary in [limitations.md](limitations.md), these are prerequisites for an authorized, process-governed investigation — not a mandate for continuous surveillance.
