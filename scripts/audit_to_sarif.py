#!/usr/bin/env python3
"""cargo audit --json の結果を SARIF 2.1.0 に変換する。

使い方:
    cargo audit --json > reports/cargo-audit.json
    python3 scripts/audit_to_sarif.py reports/cargo-audit.json reports/cargo-audit.sarif
"""
import json
import re
import sys
from pathlib import Path


def find_line(path: Path, crate: str) -> tuple[str, int]:
    """Cargo.toml に直接書かれていればその行、なければ Cargo.lock の該当行を返す。"""
    toml = Path("Cargo.toml")
    if toml.exists():
        for i, line in enumerate(toml.read_text(encoding="utf-8").splitlines(), 1):
            if re.match(rf"^\s*{re.escape(crate)}\s*=", line):
                return "Cargo.toml", i
    lock = Path("Cargo.lock")
    if lock.exists():
        for i, line in enumerate(lock.read_text(encoding="utf-8").splitlines(), 1):
            if line.strip() == f'name = "{crate}"':
                return "Cargo.lock", i
    return "Cargo.lock", 1


def level_from_cvss(cvss: str | None) -> str:
    # cvss はベクトル文字列。重大度の数値は持たないので、報告があれば error とする
    return "error" if cvss else "warning"


def main(src: str, dst: str) -> None:
    data = json.loads(Path(src).read_text(encoding="utf-8"))
    vulns = data.get("vulnerabilities", {}).get("list", [])

    rules: dict[str, dict] = {}
    results = []
    for v in vulns:
        adv = v["advisory"]
        pkg = v["package"]
        rules.setdefault(
            adv["id"],
            {
                "id": adv["id"],
                "name": adv["id"],
                "shortDescription": {"text": adv.get("title", adv["id"])},
                "helpUri": adv.get("url") or f"https://rustsec.org/advisories/{adv['id']}",
            },
        )
        file, line = find_line(Path("."), pkg["name"])
        results.append(
            {
                "ruleId": adv["id"],
                "level": level_from_cvss(adv.get("cvss")),
                "message": {"text": f"{pkg['name']} {pkg['version']}: {adv.get('title', '')}"},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {"uri": file},
                            "region": {"startLine": line},
                        }
                    }
                ],
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "cargo-audit",
                        "informationUri": "https://rustsec.org/",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    Path(dst).parent.mkdir(parents=True, exist_ok=True)
    Path(dst).write_text(json.dumps(sarif, ensure_ascii=False, indent=2), encoding="utf-8")
    print(f"{len(results)} findings -> {dst}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
