from pathlib import Path
from tempfile import TemporaryDirectory
from datetime import datetime, timezone, timedelta
from unittest.mock import patch
from exfiltrack.config import CaseConfig
from exfiltrack.pipeline import run_pipeline
from tests.support.synthetic_evtx import placeholder_evtx_file, SyntheticEvtxReader, device_lifecycle_xml, file_access_xml

base = datetime(2026, 3, 1, 9, 0, 0, tzinfo=timezone.utc)
dev_id = r'USB\VID_1234&PID_5678\SERIAL001'

out_p = Path(__file__).parent / "case_output"
out_p.mkdir(parents=True, exist_ok=True)

with TemporaryDirectory() as ev:
    ev_p = Path(ev)
    sys_log, sec_log = ev_p / 'System.evtx', ev_p / 'Security.evtx'
    placeholder_evtx_file(sys_log); placeholder_evtx_file(sec_log)
    
    records = {
        sys_log.resolve().as_posix(): [
            device_lifecycle_xml(event_id='2003', device_instance_id=dev_id, when=base, record_id=1),
            device_lifecycle_xml(event_id='2102', device_instance_id=dev_id, when=base + timedelta(minutes=10), record_id=2)
        ],
        sec_log.resolve().as_posix(): [
            file_access_xml(object_name=r'E:\Confidential\db_dump.sql', when=base + timedelta(seconds=5), record_id=10),
            file_access_xml(object_name=r'E:\Confidential\keys.pem', when=base + timedelta(seconds=12), record_id=11)
        ]
    }
    with patch('exfiltrack.parsers.evtx_parser.evtx.Evtx', SyntheticEvtxReader(records)):
        result = run_pipeline(CaseConfig(evidence_dir=ev_p, case_output_dir=out_p, case_id='DEMO-001', examiner='Examiner'))
        print('Pipeline executed successfully!')
        print(f'Detected Findings: {len(result.findings)}')
        for f in result.findings:
            print(f'  Device: {f.scored_session.session.device}')
            print(f'  Risk Score: {f.scored_session.total_score}')
            print(f'  Confidence: {f.confidence.level.value}')
        print(f'\nReports successfully exported to: {out_p.resolve()}')
        for name, path in result.report_paths.items():
            print(f'  - {name}: {path.name} ({path.stat().st_size} bytes)')

