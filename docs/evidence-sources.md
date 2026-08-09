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

The parser consumes the Shell Link header, LinkInfo, and StringData fields
read-only. It records the target path, target size and attributes, the three
header FILETIME values, and (where present) LinkInfo's volume serial number
and drive type. A `removable` drive type helps attribute the shortcut target to
a removable volume, but its volume serial is not a USB-device serial number
and must not be used as a definitive physical-device identity.

The parser does not resolve shortcut targets against the analyst workstation.
It emits separate creation, access, and modification timeline entries. The
access entry means the shortcut recorded access to the target; it is not proof
that the file was copied.

## 4. Jump Lists

**Parser:** `parsers/jumplist_parser.py` (Thabrew)

The parser consumes Windows Jump List artifacts (`.automaticDestinations-ms` and `.customDestinations-ms`) read-only, resolving the 16-character hexadecimal AppID in the filename to known applications (e.g., Windows Explorer, Microsoft Word). Unknown AppIDs are preserved as `unknown (<appid>)` to ensure no evidence is lost.

For `automaticDestinations-ms` (OLE Compound Files), the parser enumerates streams (skipping the `DestList` routing stream) and processes each numbered stream as a shortcut. For `customDestinations-ms`, it linearly carves embedded LNK files by scanning for the Shell Link header signature (`4C 00 00 00 01 14 02 ...`).

Each valid extracted shortcut is passed to the underlying `lnk_parser` routines to retain exact shortcut semantics, emitting `file_created`, `file_access`, and `file_modified` timeline entries with UTC-normalized timestamps. The event `details` payload is augmented with the jump list provenance, including the `app_id`, resolved `application`, and (for automatic destinations) the `stream_name`.

Corrupt or malformed embedded entries within a container are skipped defensively, preventing a single malformed stream from aborting the entire artifact parsing.

## 5. Reliability and Provenance

_To document, per source: what it proves, what it only suggests, and known ways it can be misleading._

## 6. Acquisition Notes

_To document: how a tester should export each artifact from a Windows VM without altering it._
