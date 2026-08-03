# Limitations

**Owner:** All members
**Tracking issue:** #14 - Final Documentation

Stating boundaries clearly is part of responsible forensic tool design. A tool that claims to catch everything is less trustworthy than one that is precise about its actual evidentiary reach.

**This file is mandatory reading before interpreting any ExfilTrack output.**

---

## The Core Limitation

> ExfilTrack identifies activity consistent with possible USB-based data exfiltration. Temporal correlation alone does not prove that a file was copied.

A file being accessed shortly after a USB device was inserted is evidence consistent with exfiltration. It is not proof of it. The same artifact pattern is produced by an employee legitimately opening a file while a USB device happens to be connected.

## Category 1 - Outside Scope (Organizational IT Policy)

Some exfiltration channels are best closed through administrative policy rather than forensic software, because they can be blocked with no impact on legitimate developer work. ExfilTrack assumes these as organizational prerequisites and does not implement them:

- Restricting personal mobile-device sync profiles
- Blocking unauthorized removable-storage classes via Group Policy
- Centralizing log forwarding

## Category 2 - Addressed by ExfilTrack

Behaviours that rely on tools developers legitimately need every day (command-line utilities, local compilation, archive creation) cannot be blocked without breaking normal engineering work. Here ExfilTrack's value is post-incident detection, not prevention. This is the core of the tool's contribution.

## Category 3 - Documented Limitations

Scenarios that cannot be reliably detected by an offline artifact-analysis tool:

- **Clipboard data pasted into approved communication platforms.** This involves encrypted application traffic and volatile memory that is unavailable once the machine is powered off.
- **Encrypted archive contents.** ExfilTrack can show that an archive was created and moved to removable storage, but cannot decrypt or verify the contents of a password-protected archive without the passphrase.
- **Exfiltration purely through memory or network sockets.** If data never touches non-volatile disk storage, it leaves no artifact for ExfilTrack to find. The tool performs no live memory or network capture.

## Additional Technical Limitations

_To document as implementation proceeds. Expected entries:_

- Event log channels relevant to device mounting are frequently disabled by default, so the absence of an EVTX event does not mean the activity did not occur.
- Registry `USBSTOR` timestamps record device first/last connection, not per-file activity.
- Shortcut and Jump List timestamps record access, not copying. A file can be read without being copied and copied without being opened.
- DOS timestamps have two-second resolution, which limits precision in the 30-second scoring window.
- Timezone information is absent from some artifacts. Where an offset must be assumed, the assumption is disclosed in the report.
- Artifacts can be deliberately deleted or altered by a knowledgeable user. ExfilTrack detects absence, not the reason for absence.

## How Findings Should Be Used

Where destination-device artifacts or cryptographic hash matches are available, ExfilTrack can provide stronger confirmation of file transfer. Otherwise its findings should be treated as **leads for further investigation rather than conclusions**.

## Ethical Boundary

ExfilTrack analyzes artifacts that may include personal file names and USB device history. Its use should be governed by organizational policy and applicable law regarding employee monitoring and data forensics. It is designed for authorized investigators on company-owned equipment as part of a defined incident-response process, not for covert or unauthorized surveillance.
