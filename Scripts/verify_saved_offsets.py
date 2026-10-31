from pathlib import Path
import json,sys
R=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else Path(__file__).resolve().parent
checks=json.loads((R/'analysis/memory_offset_verification.json').read_text())
with (R/'working/01931.bin').open('rb') as f:
    for c in checks:
        f.seek(c['reported_offset']); b=c['text'].encode()
        assert f.read(len(b))==b, c['reported_offset']
print(f'{len(checks)}/{len(checks)} saved offset checks match raw capture')
