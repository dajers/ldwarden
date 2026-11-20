from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from app.analysis.sca.engine import SCAAnalyzer
from app.analysis.sast.engine import SASTAnalyzer
from app.analysis.secrets.engine import SecretAnalyzer
from app.ai.service import AIService
from app.config import BASE_DIR, load_settings
from app.core.models import dedupe_findings, max_severity, severity_counts, sort_findings
from app.core.source import SourceService
from app.reports.builder import build_all


def _run_analyzers(settings, target_path: str | None = None):
    source = SourceService(settings).resolve(
        {"kind": "path", "path": target_path} if target_path else {"kind": "default"}
    )
    findings = []
    stats = []
    for analyzer in (
        SecretAnalyzer(),
        SCAAnalyzer(settings.vulnerability_db_path),
        SASTAnalyzer(),
    ):
        result = analyzer.analyze(source)
        findings.extend(result.findings)
        stats.append({"analyzer": analyzer.name, "stats": result.stats, "warnings": result.warnings})
    findings = sort_findings(dedupe_findings(findings))
    return source, findings, stats


def command_scan(args) -> int:
    settings = load_settings({"seed_templates": False})
    source, findings, stats = _run_analyzers(settings, args.path)
    ai_result = None
    if args.ai:
        if args.provider:
            settings.llm_provider = args.provider
        ai_result = AIService(settings).analyze(
            findings,
            meta={"source": source.to_dict(), "counts": severity_counts(findings)},
        )
    run_info = {
        "id": "cli",
        "workflow_name": "CLI scan",
        "status": "failed" if findings else "success",
        "trigger": "manual",
        "source_label": source.label,
    }
    if args.format == "summary":
        counts = severity_counts(findings)
        print(f"Источник: {source.label} ({len(source.files)} файлов)")
        print(
            f"Находок: {counts['total']}  CRITICAL={counts['CRITICAL']} HIGH={counts['HIGH']} "
            f"MEDIUM={counts['MEDIUM']} LOW={counts['LOW']}  max={max_severity(findings) or '—'}"
        )
        for finding in findings:
            print(
                f"  {finding.severity:8s} {finding.category:6s} {finding.class_name:32s} "
                f"{finding.path}:{finding.line}"
                + (f"  {finding.advisory_id}" if finding.advisory_id else "")
            )
        for item in stats:
            print(f"  [{item['analyzer']}] {item['stats']}")
        return 0
    reports = build_all(findings, run_info, ai=ai_result, source=source.to_dict())
    if args.format == "json":
        output = reports["json"]
    elif args.format == "sarif":
        output = reports["sarif"]
    else:
        output = reports["md"]
    if args.out:
        Path(args.out).write_text(output, encoding="utf-8")
        print(f"Отчёт записан: {args.out}")
    else:
        print(output)
    return 0


def command_check(args) -> int:
    settings = load_settings({"seed_templates": False})
    source, findings, _stats = _run_analyzers(settings, args.path)
    ground_truth_path = Path(args.ground_truth or BASE_DIR / "training-main" / "ground-truth" / "training-findings.json")
    if not ground_truth_path.exists():
        print(f"Эталон не найден: {ground_truth_path}", file=sys.stderr)
        return 2
    ground_truth = json.loads(ground_truth_path.read_text(encoding="utf-8"))

    def matches(expected: dict, finding) -> bool:
        if expected.get("category") != finding.category or expected.get("path") != finding.path:
            return False
        if expected["category"] in {"SECRET", "SAST"}:
            if expected.get("class") != finding.class_name:
                return False
            expected_line = expected.get("line")
            expected_end = expected.get("endLine", expected_line)
            actual_end = finding.end_line or finding.line
            return not (actual_end < expected_line or finding.line > expected_end)
        if expected.get("group") != finding.group or expected.get("artifact") != finding.artifact:
            return False
        if expected.get("version") != finding.version:
            return False
        actual_ids = set(finding.advisory_ids or [])
        if finding.advisory_id:
            actual_ids.add(finding.advisory_id)
        return bool(actual_ids & set(expected.get("advisoryIds", [])))

    matched, missed = [], []
    for expected in ground_truth.get("findings", []):
        if any(matches(expected, finding) for finding in findings):
            matched.append(expected["id"])
        else:
            missed.append(expected["id"])
    control_hits = []
    for control in ground_truth.get("controls", []):
        for finding in findings:
            if finding.path != control["path"] or finding.category != control["category"]:
                continue
            line = control.get("line", 1)
            end = control.get("endLine", line)
            if finding.line <= end and (finding.end_line or finding.line) >= line:
                control_hits.append((control["id"], finding.class_name, finding.line))
    total = len(ground_truth.get("findings", []))
    print(f"Эталон: {total} находок; найдено {len(matched)}; пропущено {len(missed)}")
    if missed:
        print("Пропущены: " + ", ".join(missed))
    if control_hits:
        print("Ложные срабатывания на controls:")
        for item in control_hits:
            print("  ", item)
    else:
        print("Controls: ложных срабатываний нет")
    print(f"Всего находок анализаторов: {len(findings)}")
    if args.json:
        print(
            json.dumps(
                {
                    "matched": matched,
                    "missed": missed,
                    "control_hits": control_hits,
                    "total_findings": len(findings),
                },
                ensure_ascii=False,
                indent=2,
            )
        )
    return 0 if not missed and not control_hits else 1


def command_serve(args) -> int:
    from app.api.app import create_app

    settings = load_settings()
    flask_app = create_app(settings)
    flask_app.run(
        host=args.host,
        port=args.port,
        debug=args.debug,
        threaded=True,
        use_reloader=False,
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="LDWarden backend")
    sub = parser.add_subparsers(dest="command")

    serve = sub.add_parser("serve", help="Запустить Flask API")
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=8000)
    serve.add_argument("--debug", action="store_true")

    scan = sub.add_parser("scan", help="Запустить анализаторы на проекте")
    scan.add_argument("--path", default=None, help="Путь к проекту (по умолчанию training-project)")
    scan.add_argument("--format", choices=["summary", "md", "json", "sarif"], default="summary")
    scan.add_argument("--out", default=None)
    scan.add_argument("--ai", action="store_true", help="Добавить AI-объяснение")
    scan.add_argument("--provider", default=None)
    scan.set_defaults(func=command_scan)

    check = sub.add_parser("check", help="Сверить анализаторы с эталоном организаторов")
    check.add_argument("--path", default=None)
    check.add_argument("--ground-truth", default=None)
    check.add_argument("--json", action="store_true")
    check.set_defaults(func=command_check)
    serve.set_defaults(func=command_serve)
    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not getattr(args, "command", None):
        args = parser.parse_args(["serve"])
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
