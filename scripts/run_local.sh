#!/usr/bin/env bash
# CI（.github/workflows/security.yml）と同じ検査を手元で実行する。
# 必要なもの: cargo, cargo-audit, cargo-deny, clippy-sarif, semgrep, gitleaks, checkov, python3 + pyyaml
set -u
cd "$(dirname "$0")/.."
mkdir -p reports

echo "== clippy"
cargo clippy --message-format=json 2>/dev/null | clippy-sarif > reports/clippy.sarif

echo "== cargo audit"
cargo audit --json > reports/cargo-audit.json 2>/dev/null
python3 scripts/audit_to_sarif.py reports/cargo-audit.json reports/cargo-audit.sarif

echo "== cargo deny（SARIFは出さず、結果だけ表示）"
cargo deny check advisories licenses sources 2>&1 | tail -n 1

echo "== semgrep（自作ルール）"
semgrep scan --config .semgrep --metrics=off --disable-version-check --quiet \
  --sarif --output reports/semgrep.sarif src

echo "== gitleaks"
gitleaks dir . --config .gitleaks.toml --no-banner --exit-code 0 \
  --report-format sarif --report-path reports/gitleaks.sarif 2>/dev/null

echo "== checkov（Dockerfile）"
checkov -f Dockerfile --framework dockerfile --quiet --soft-fail --skip-download \
  -o sarif --output-file-path reports > /dev/null
mv -f reports/results_sarif.sarif reports/checkov.sarif 2>/dev/null

echo "== 正解表と照合"
python3 scripts/summarize.py reports eval/ground_truth.yaml | tee reports/summary.md
