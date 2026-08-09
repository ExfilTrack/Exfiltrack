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

The parser opens exported EVTX files read-only through `python-evtx`. It
recognises the following narrow set of records and retains the event provider,
ID, record ID (when present), and channel (when present) in each event's
`details` field.

| Provider / event ID | Normalized event | What it establishes | What it does **not** establish |
| --- | --- | --- | --- |
| `Microsoft-Windows-DriverFrameworks-UserMode`, 2003 | `usb_insert` | A UMDF device-connection workflow began for the recorded device instance. | That the device was a mass-storage device, received a drive letter, or a file was copied. |
| `Microsoft-Windows-DriverFrameworks-UserMode`, 2100 | `usb_remove_pending` | The device's UMDF connection was entering a removal workflow. | That removal completed; this event is deliberately not a session end. |
| `Microsoft-Windows-DriverFrameworks-UserMode`, 2102 | `usb_remove` | A final UMDF device-disconnection workflow was recorded. | That physical removal happened at the exact timestamp on every Windows/device-driver version. |
| `Microsoft-Windows-Kernel-PnP`, 20001 or 20003 | `usb_device_install` | A Plug and Play driver-install/service-add stage was recorded for the device instance. | A physical insertion, a completed installation, or device availability. These events are not used as session boundaries. |
| `Microsoft-Windows-Security-Auditing`, 4663, `ObjectType=File` | `file_access` | The configured Windows audit policy recorded access to the named file object. | A copy to a USB device, successful transfer, or a file's contents being read. `AccessMask` and process fields are retained for review. |

The DriverFrameworks operational channel is commonly exported separately from
`System.evtx`; the parser identifies records by provider and event ID rather
than trusting the filename, so an exported or renamed log remains analysable.
Security 4663 is emitted only when the relevant audit policy and SACL are in
place. Non-file 4663 records (for example registry-key access) are excluded.

The `usb_device_install` and `usb_remove_pending` lifecycle labels preserve
useful evidence for the report appendix. Only `usb_insert` and `usb_remove`
are session boundaries for correlation.

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
