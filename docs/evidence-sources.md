# Evidence Sources

**Owner:** Thabrew D. C. L.
**Tracking issues:** #3, #4, #5, #6

Status: outline. Sections are placeholders to be filled as each parser is implemented.

---

## Version 1 Scope

| Source | Purpose |
| --- | --- |
| Registry hives (`SYSTEM`, `SOFTWARE`, `NTUSER.DAT`) | Identify USB storage devices, vendor/product data, device identifiers |
| Windows Event Logs (`System.evtx`, `Security.evtx`) | Detect storage-driver mount and unmount events |
| Shortcut files (`.lnk`) | Extract target file paths, sizes, access/modification timestamps |
| Jump Lists | Identify recently and frequently accessed documents per application |

## 1. Registry Hives

**Parser:** `parsers/registry_parser.py` (Milindu)

_To document: keys of interest, what each yields, and their reliability._

Planned coverage:

- `SYSTEM\CurrentControlSet\Enum\USBSTOR` - device instances, vendor and product strings, serial numbers
- `SYSTEM\MountedDevices` - drive letter to volume mappings
- `SOFTWARE\Microsoft\Windows Portable Devices\Devices` - friendly names
- `NTUSER.DAT\...\MountPoints2` - per-user volume GUIDs

## 2. Windows Event Logs

**Parser:** `parsers/evtx_parser.py` (Thabrew)

_To document: channels, providers, and event IDs used, and what each proves._

Planned coverage:

- Storage driver mount and unmount events
- Device install and removal events
- Caveat: relevant channels are frequently disabled by default, so absence of an event is not absence of the activity

## 3. Shortcut Files (`.lnk`)

**Parser:** `parsers/lnk_parser.py` (Thabrew)

_To document: structure fields consumed, timestamp semantics, and volume identification._

Planned coverage:

- Target path, size, and attributes
- Creation, access, and modification timestamps
- Volume serial number and drive type, used to attribute a file to a removable volume

## 4. Jump Lists

**Parser:** `parsers/jumplist_parser.py` (Thabrew)

_To document: AppID mapping, embedded shortcut extraction, and per-application semantics._

Planned coverage:

- `automaticDestinations-ms` - recent and frequent entries
- `customDestinations-ms` - application-defined entries

## 5. Reliability and Provenance

_To document, per source: what it proves, what it only suggests, and known ways it can be misleading._

## 6. Acquisition Notes

_To document: how a tester should export each artifact from a Windows VM without altering it._
