#!/usr/bin/env python3
"""reports/ 以下の SARIF を集めて、正解表（eval/ground_truth.yaml）と照合する。

使い方:
    python3 scripts/summarize.py reports eval/ground_truth.yaml > reports/summary.md

出力は Markdown。GitHub Actions では $GITHUB_STEP_SUMMARY に流す。
"""
import json
import sys
from collections import defaultdict
from pathlib import Path

import yaml

LINE_TOLERANCE = 2  # 指摘行のずれをどこまで同じ箇所とみなすか


def load_findings(report_dir: Path) -> list[dict]:
    findings = []
    for sarif_path in sorted(report_dir.rglob("*.sarif")):
        data = json.loads(sarif_path.read_text(encoding="utf-8"))
        for run in data.get("runs", []):
            tool = run["tool"]["driver"]["name"]
            for r in run.get("results", []):
                loc = (r.get("locations") or [{}])[0].get("physicalLocation", {})
                uri = loc.get("artifactLocation", {}).get("uri", "")
                line = loc.get("region", {}).get("startLine", 0)
                rule = (r.get("ruleId") or "").split(".")[-1]
                findings.append(
                    {
                        "tool": tool,
                        "rule": rule,
                        "file": uri.removeprefix("./").removeprefix("file://"),
                        "line": line,
                        "message": (r.get("message") or {}).get("text", "").strip(),
                    }
                )
    return findings


def matches(finding: dict, item: dict) -> bool:
    rules = item.get("match_rules") or ([item["rule"]] if "rule" in item else [])
    if "advisory" in item:
        rules = rules + [item["advisory"]]
    if rules:
        return finding["rule"] in rules
    if not finding["file"].endswith(item["file"]):
        return False
    return any(abs(finding["line"] - ln) <= LINE_TOLERANCE for ln in item.get("lines", []))


def main(report_dir: str, truth_path: str) -> None:
    findings = load_findings(Path(report_dir))
    truth = yaml.safe_load(Path(truth_path).read_text(encoding="utf-8"))
    used: set[int] = set()

    out = ["## 検出結果（ツール）", ""]
    out.append(f"SARIF から読み込んだ指摘：{len(findings)} 件")
    out.append("")
    out.append("| ID | 脆弱性 | 想定 | 検出したツール | 判定 |")
    out.append("|---|---|---|---|---|")

    tool_expected = 0
    tool_hit = 0
    for v in truth["vulnerabilities"]:
        hit_tools = set()
        for i, f in enumerate(findings):
            if matches(f, v):
                hit_tools.add(f["tool"])
                used.add(i)
        expected = "・".join(v["expected"])
        if "tool" in v["expected"]:
            tool_expected += 1
            tool_hit += bool(hit_tools)
            verdict = "検出" if hit_tools else "**見逃し**"
        else:
            verdict = "検出（想定外）" if hit_tools else "LLM担当"
        out.append(
            f"| {v['id']} | {v['title']} | {expected} | {', '.join(sorted(hit_tools)) or '-'} | {verdict} |"
        )

    out += ["", f"ツール担当 {tool_expected} 件のうち {tool_hit} 件を検出", ""]

    unplanted_hits = defaultdict(set)
    for u in truth.get("unplanted", []):
        for i, f in enumerate(findings):
            if matches(f, u):
                unplanted_hits[u["id"]].add(f["tool"])
                used.add(i)
    if truth.get("unplanted"):
        out += ["### 仕込んでいない実在の指摘", "", "| ID | 内容 | 状態 | 検出したツール |", "|---|---|---|---|"]
        for u in truth["unplanted"]:
            what = u.get("crate") or u.get("rule")
            out.append(f"| {u['id']} | {what} | {u['status']} | {', '.join(sorted(unplanted_hits[u['id']])) or '-'} |")
        out.append("")

    rest = [f for i, f in enumerate(findings) if i not in used]
    out += ["### 正解表にない指摘（誤検知の候補）", ""]
    if rest:
        out += ["| ツール | ルール | 場所 |", "|---|---|---|"]
        for f in rest:
            out.append(f"| {f['tool']} | {f['rule']} | {f['file']}:{f['line']} |")
    else:
        out.append("なし")
    print("\n".join(out))


if __name__ == "__main__":
    if len(sys.argv) != 3:
        sys.exit(__doc__)
    main(sys.argv[1], sys.argv[2])
