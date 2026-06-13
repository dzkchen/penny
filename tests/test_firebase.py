from __future__ import annotations

from pathlib import Path

from penny.detectors import (
    detect_client_side_db_writes,
    detect_permissive_firebase_rules,
    run_detectors,
)
from penny.repo import SourceFile, walk_repo


def _src(name: str, text: str) -> SourceFile:
    return SourceFile(path=Path(name), relative_path=name, text=text)


def test_firebase_client_writes_flagged() -> None:
    files = [
        _src("src/db.ts", "await setDoc(doc(db, 'users', uid), data);\n"),
        _src("src/v8.ts", "db.collection('orders').doc(id).set(payload);\n"),
        _src("src/add.ts", "await db.collection('transactions').add(payload);\n"),
        _src("src/rtdb.ts", "set(ref(db, 'balances/' + uid), amount);\n"),
        _src("src/app/api/admin/route.ts", "await db.collection('x').add(y);\n"),  # server: excluded
    ]

    findings = detect_client_side_db_writes(files)

    assert {f.location.file for f in findings} == {"src/db.ts", "src/v8.ts", "src/add.ts", "src/rtdb.ts"}
    assert all(f.detector_id == "D012" for f in findings)


def test_permissive_firestore_rules_flagged_high() -> None:
    rules = _src(
        "firestore.rules",
        "match /databases/{db}/documents {\n  match /{doc=**} {\n    allow read, write: if true;\n  }\n}\n",
    )

    findings = detect_permissive_firebase_rules([rules])

    assert len(findings) == 1
    assert findings[0].detector_id == "D013"
    assert findings[0].severity == "High"


def test_realtime_db_open_rules_json_flagged() -> None:
    rules = _src("database.rules.json", '{"rules": {".read": true, ".write": true}}\n')

    findings = detect_permissive_firebase_rules([rules])

    assert [f.detector_id for f in findings].count("D013") >= 1


def test_auth_only_rule_is_medium() -> None:
    rules = _src("firestore.rules", "    allow read, write: if request.auth != null;\n")

    findings = detect_permissive_firebase_rules([rules])

    assert len(findings) == 1
    assert findings[0].severity == "Medium"


def test_scoped_ownership_rule_not_flagged() -> None:
    rules = _src("firestore.rules", "    allow read, write: if request.auth.uid == resource.data.ownerId;\n")

    assert detect_permissive_firebase_rules([rules]) == []


def test_rules_files_are_scanned_by_walker(tmp_path) -> None:
    (tmp_path / "firestore.rules").write_text("allow read, write: if true;\n", encoding="utf-8")

    findings = run_detectors(walk_repo(tmp_path))

    assert any(f.detector_id == "D013" for f in findings)
