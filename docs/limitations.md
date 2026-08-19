# Limitations

**Owner:** All members
**Tracking issue:** #14 - Final Documentation

Stating boundaries clearly is part of responsible forensic tool design. A tool that claims to catch everything is less trustworthy than one that is precise about its actual evidentiary reach.

**This file is mandatory reading before interpreting any ExfilTrack output.**

---

## The Core Limitation

> ExfilTrack identifies activity consistent with possible USB-based data exfiltration. Temporal correlation alone does not prove that a file was copied.

A file being accessed shortly after a USB device was inserted is evidence consistent with exfiltration. It is not proof of it. The same artifact pattern is produced by an employee legitimately opening a file while a USB device happens to be connected.

## The Second Core Limitation

> ExfilTrack's evidentiary reach is a function of how the endpoint was configured **before** the incident. Absence of evidence in a report is not evidence of absence.

Some artifacts ExfilTrack reads do not exist unless an administrator enabled them in advance. Others exist by default but can be deleted afterwards — in several cases by a standard user with no administrator rights at all.

This produces a silent failure mode. ExfilTrack does not error when an artifact was never created or has been wiped. It runs normally, finds nothing, and produces a clean report. A clean report from an unconfigured endpoint reads exactly like an exoneration.

The full dependency analysis and the controls that address it are in **[organizational-prerequisites.md](organizational-prerequisites.md)**. The short version, scoped to the V1 parsers:

| V1 evidence | Failure mode | Admin needed to defeat? |
|---|---|---|
| DriverFrameworks 2003 / 2100 / 2102 | Channel is **disabled by default** on Windows 10/11 — the events never exist | n/a, never enabled |
| Security 4663 | Requires object-access auditing **and** a SACL — absent by default | n/a, never enabled |
| `.lnk` files, Jump Lists | User deletes `Recent\`, or disables recent-items tracking | **No** |
| `NTUSER.DAT\...\MountPoints2` | User deletes their own subkeys | **No** |
| `USBSTOR`, `MountedDevices` | USB history cleaners remove the device subkeys | Yes |
| Event logs generally | Cleared with `wevtutil cl`, or wrapped by default log sizes | Yes |
| Every artifact | Employee boots a live USB or removes the drive — no Windows artifacts generated | No, physical access only |

The first two rows mean the corresponding evidence is **never generated** on a default machine. The next two mean two and a half of the four V1 parsers can be defeated without elevation, so removing local administrator rights — the strongest single control elsewhere — does not help. Volume Shadow Copies are the main mitigation there, which is a direct argument for prioritizing the planned VSS ingestion module.

## Category 1 - Outside Scope (Organizational IT Policy)

Some exfiltration channels are best closed through administrative policy rather than forensic software, because they can be blocked with little or no impact on legitimate developer work. A second set of policies blocks nothing at all, and exists purely to preserve or generate the evidence ExfilTrack reads. ExfilTrack assumes both as organizational prerequisites and does not implement them.

**Channel restriction:**

- Restricting personal mobile-device sync profiles
- Blocking unauthorized removable-storage classes via Group Policy — across all classes, not USB alone
- Blocking Bluetooth file transfer, which produces no `USBSTOR` artifact of any kind
- Enforcing BitLocker To Go with escrowed recovery keys, without which a recovered destination device may be unreadable and `Confirmed` confidence unreachable

**Evidence preservation:**

- Centralizing log forwarding
- Revoking the right to clear event logs, and raising default log sizes
- Removing standing local administrator rights
- Retaining Volume Shadow Copies, the only recovery path for artifacts a standard user deleted
- Enforcing Explorer recent-items and Jump List tracking so it cannot be switched off per-user
- Application allowlisting against USB-history-cleaning utilities

**Evidence generation:**

- Enabling `Microsoft-Windows-DriverFrameworks-UserMode/Operational`, which is off by default
- Enabling object-access auditing with SACLs on protected directories, and on the `Recent` folder and `MountPoints2` key so that deletion of the evidence is itself logged
- Enabling removable-storage auditing

**Boot integrity:**

- Full-disk encryption with pre-boot authentication, a UEFI supervisor password, Secure Boot, and disabled USB boot — without which the entire tool is bypassed by booting another operating system

Each of these is specified with Group Policy paths, verification commands, and an honest developer-impact assessment in [organizational-prerequisites.md](organizational-prerequisites.md).

## Category 2 - Addressed by ExfilTrack

Behaviours that rely on tools developers legitimately need every day (command-line utilities, local compilation, archive creation) cannot be blocked without breaking normal engineering work. Here ExfilTrack's value is post-incident detection, not prevention. This is the core of the tool's contribution.

Note that Category 2 is not independent of Category 1. Every parser reads an artifact whose existence depends on the configuration above. A forensic tool that depends on an artifact an insider can delete is not a control by itself — it becomes a control when paired with the policy that prevents the deletion.

## Category 3 - Documented Limitations

Scenarios that cannot be reliably detected by an offline artifact-analysis tool:

- **Clipboard data pasted into approved communication platforms.** This involves encrypted application traffic and volatile memory that is unavailable once the machine is powered off.
- **Encrypted archive contents.** ExfilTrack can show that an archive was created and moved to removable storage, but cannot decrypt or verify the contents of a password-protected archive without the passphrase.
- **Exfiltration purely through memory or network sockets.** If data never touches non-volatile disk storage, it leaves no artifact for ExfilTrack to find. The tool performs no live memory or network capture.
- **Alternative execution environments.** Shell history and process activity inside a WSL distribution live in an ext4 VHDX that ExfilTrack does not parse, and guest-VM filesystem activity is opaque to host-level artifacts. Writes reaching a mounted Windows path are still visible to the filesystem, but the commands that produced them are not.
- **Analog capture.** Photographing the screen. No endpoint control or disk artifact addresses this; it is bounded by throughput and by physical-security policy.

## Additional Technical Limitations

_To document as implementation proceeds. Expected entries:_

- The `Microsoft-Windows-DriverFrameworks-UserMode/Operational` channel used for USB connection and removal evidence is frequently disabled by default. Security event 4663 also exists only when object-access auditing and the relevant SACL are configured. Therefore, the absence of an EVTX event does not guarantee the activity did not occur.
- Registry `USBSTOR` timestamps record device first/last connection, not per-file activity.
- Properties `0066` and `0067` are overwritten on each connection, so only the most recent session survives in the registry. Earlier connections are recoverable only from event logs or shadow copies.
- A serial number whose second character is `&` was generated by Windows and identifies a port path, not a physical device. It cannot attribute activity across machines.
- A `.lnk` volume serial number is not a USB device serial number. It can associate a target with a removable volume, but must not be treated as definitive physical-device identity.
- Shortcut and Jump List timestamps record access, not copying. A file can be read without being copied and copied without being opened.
- DOS timestamps have two-second resolution, which limits precision in the 30-second scoring window.
- Timezone information is absent from some artifacts. Where an offset must be assumed, the assumption is disclosed in the report.
- Artifacts can be deliberately deleted or altered by a knowledgeable user. ExfilTrack detects absence, not the reason for absence.
- All correlation assumes a monotonic, accurate system clock. Clock manipulation on the source machine is not currently detected.

## How Findings Should Be Used

Where destination-device artifacts or cryptographic hash matches are available, ExfilTrack can provide stronger confirmation of file transfer. Otherwise its findings should be treated as **leads for further investigation rather than conclusions**.

When reading a report that found little or nothing, check the Evidence Coverage section first. A report from an endpoint where the DriverFrameworks channel was disabled and object-access auditing was never configured has not established that nothing happened — it has established that the question could not be asked.

## Ethical Boundary

ExfilTrack analyzes artifacts that may include personal file names and USB device history. Its use should be governed by organizational policy and applicable law regarding employee monitoring and data forensics. It is designed for authorized investigators on company-owned equipment as part of a defined incident-response process, not for covert or unauthorized surveillance.
