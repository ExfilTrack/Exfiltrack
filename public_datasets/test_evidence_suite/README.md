# ExfilTrack Test Evidence Suite (Public Dataset Copies)

This directory contains curated, structured test evidence sets created from public EVTX datasets:
- `hayabusa-sample-evtx` (Yamato Security)
- `evtx-attack-samples` (Samir Bousseaden)

**Note:** All original datasets under `public_datasets/` remain intact and unmodified. The cases below are isolated copies organized in ExfilTrack's standard forensic evidence directory structure.

## Test Case Layout

```
test_evidence_suite/
├── case_01_credential_access/
│   └── evtx/
│       └── Security.evtx (Source: evtx-attack-samples/Credential Access/CA_chrome_firefox_opera_4663.evtx)
│           - Tests extraction of genuine Security 4663 File Access events on Chrome, Firefox, and Opera credential stores.
│
├── case_02_apt28_file_stealer/
│   └── evtx/
│       └── Security.evtx (Source: hayabusa-sample-evtx/EVTX-ATTACK-SAMPLES/Other/APT28-CredentialStealer.evtx)
│           - Tests extraction of Security 4663 File Access events related to browser cookie and login theft.
│
├── case_03_system_activity/
│   └── evtx/
│       └── System.evtx (Source: hayabusa-sample-evtx/DeepBlueCLI/metasploit-psexec-powershell-target-system.evtx)
│           - Tests ingestion and processing of real Windows System event log structures.
│
├── case_04_defense_evasion/
│   └── evtx/
│       └── Security.evtx (Source: evtx-attack-samples/Defense Evasion/DE_1102_security_log_cleared.evtx)
│           - Tests handling of security logs without file access (clean zero-finding handling without parser crashes).
│
└── case_05_combined_usb_exfil/
    ├── evtx/
    │   ├── DriverFrameworks-UserMode.evtx (USB plug/unplug lifecycle events)
    │   └── Security.evtx (Real 4663 browser credential access events)
    ├── registry/
    │   ├── SYSTEM (USBSTOR and MountedDevices)
    │   ├── SOFTWARE (Portable Devices labels)
    │   └── NTUSER.DAT (MountPoints2 user volume mount)
    └── lnk/
        └── prod_export.sql.lnk (Shortcut file access)
    - Full end-to-end integration test combining public real-world file access logs with USB device correlation.
```

## Running Analysis

Execute with ExfilTrack CLI:
```powershell
exfiltrack analyze --evidence public_datasets/test_evidence_suite/case_01_credential_access --case-dir cases-outputs/public_case_01 --case-id PUB-01 --examiner "Forensic Examiner"
```
Or run the automated test suite runner:
```powershell
python scripts/run_public_dataset_tests.py
```
