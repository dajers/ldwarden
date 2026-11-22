from __future__ import annotations

import json
import unittest
from pathlib import Path

from app.analysis.sca.engine import SCAAnalyzer
from app.analysis.sca.gradle import parse_build_gradle
from app.analysis.sca.version import compare_versions, version_in_range, version_in_ranges
from app.analysis.sast.engine import SASTAnalyzer
from app.analysis.secrets.engine import SecretAnalyzer
from app.config import BASE_DIR, load_settings
from app.core.source import SourceService, build_tree

TRAINING = BASE_DIR / "training-main" / "training-project"
GROUND_TRUTH = BASE_DIR / "training-main" / "ground-truth" / "training-findings.json"


def _matches(expected: dict, finding) -> bool:
    if expected.get("category") != finding.category or expected.get("path") != finding.path:
        return False
    if expected["category"] in {"SECRET", "SAST"}:
        if expected.get("class") != finding.class_name:
            return False
        line = expected.get("line", 1)
        end = expected.get("endLine", line)
        return not ((finding.end_line or finding.line) < line or finding.line > end)
    if expected.get("group") != finding.group or expected.get("artifact") != finding.artifact:
        return False
    if expected.get("version") != finding.version:
        return False
    actual = set(finding.advisory_ids or [])
    if finding.advisory_id:
        actual.add(finding.advisory_id)
    return bool(actual & set(expected.get("advisoryIds", [])))


class AnalyzerGroundTruthTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = load_settings({"seed_templates": False})
        cls.tree = SourceService(cls.settings).resolve({"kind": "path", "path": str(TRAINING)})
        cls.findings = []
        for analyzer in (
            SecretAnalyzer(),
            SCAAnalyzer(cls.settings.vulnerability_db_path),
            SASTAnalyzer(),
        ):
            cls.findings.extend(analyzer.analyze(cls.tree).findings)
        cls.ground_truth = json.loads(GROUND_TRUTH.read_text(encoding="utf-8"))

    def test_all_ground_truth_findings_are_detected(self):
        matched = []
        missed = []
        for expected in self.ground_truth["findings"]:
            if any(_matches(expected, finding) for finding in self.findings):
                matched.append(expected["id"])
            else:
                missed.append(expected["id"])
        self.assertEqual(missed, [], f"Пропущены эталонные находки: {missed}")
        self.assertEqual(len(matched), 15)

    def test_no_false_positives_on_controls(self):
        hits = []
        for control in self.ground_truth["controls"]:
            line = control.get("line", 1)
            end = control.get("endLine", line)
            for finding in self.findings:
                if finding.path != control["path"] or finding.category != control["category"]:
                    continue
                if finding.line <= end and (finding.end_line or finding.line) >= line:
                    hits.append((control["id"], finding.class_name, finding.line))
        self.assertEqual(hits, [])

    def test_exactly_fifteen_findings(self):


        self.assertEqual(len(self.findings), 15)

    def test_secret_values_are_masked(self):
        raw_fragments = ["cg26_parts_", "cg26_quote_", "cg26_depot_", "cg26_warranty_", "cg26_pickup_"]
        for finding in self.findings:
            if finding.category != "SECRET":
                continue
            blob = json.dumps(finding.to_dict(), ensure_ascii=False)
            for fragment in raw_fragments:
                self.assertNotIn(fragment, blob, f"Секрет не замаскирован в {finding.path}:{finding.line}")

    def test_sca_advisories(self):
        sca = [finding for finding in self.findings if finding.category == "SCA"]
        self.assertEqual(len(sca), 5)
        ids = {finding.advisory_id for finding in sca}
        self.assertIn("CVE-2022-42889", ids)
        self.assertIn("CVE-2023-5072", ids)

    def test_sast_classes(self):
        sast = {finding.class_name for finding in self.findings if finding.category == "SAST"}
        self.assertEqual(
            sast,
            {
                "sql-injection",
                "tls-verification",
                "credentialed-cors",
                "route-authorization",
                "object-authorization",
            },
        )


class NestedGradleProjectTests(unittest.TestCase):
    def test_sca_finds_project_inside_cloned_repository(self):
        import tempfile

        root = Path(tempfile.mkdtemp(prefix="ldw-nested-repo-"))
        project = root / "training-project"
        project.mkdir()
        build = project / "build.gradle.kts"
        build.write_text(
            'plugins { kotlin("jvm") version "2.2.21" }\n'
            'repositories { mavenCentral() }\n'
            'dependencies {\n'
            '    implementation("org.apache.commons:commons-text:1.9")\n'
            '}\n',
            encoding="utf-8",
        )
        tree = build_tree(root)
        settings = load_settings({"seed_templates": False})
        result = SCAAnalyzer(settings.vulnerability_db_path).analyze(tree)
        self.assertEqual(len(result.findings), 1)
        self.assertEqual(result.findings[0].advisory_id, "CVE-2022-42889")
        self.assertEqual(result.stats["dependencies"], 1)

class VersionTests(unittest.TestCase):
    def test_compare_versions(self):
        self.assertEqual(compare_versions("1.9", "1.9.0"), 0)
        self.assertLess(compare_versions("1.14.1", "1.14.2"), 0)
        self.assertLess(compare_versions("20230227", "20230618"), 0)
        self.assertLess(compare_versions("3.8.0", "3.9.0"), 0)

    def test_ranges(self):
        interval = {"lower": "1.5", "lowerInclusive": True, "upper": "1.10.0", "upperInclusive": False}
        self.assertTrue(version_in_range("1.9", interval))
        self.assertFalse(version_in_range("1.10.0", interval))
        self.assertFalse(version_in_range("1.4.9", interval))
        self.assertTrue(
            version_in_ranges(
                "20230227",
                [{"lower": None, "lowerInclusive": False, "upper": "20230618", "upperInclusive": True}],
            )
        )

    def test_qualified_version_is_not_numeric(self):
        from app.analysis.sca.version import parse_version

        self.assertIsNone(parse_version("1.0-SNAPSHOT"))


class GradleParserTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.project = parse_build_gradle(TRAINING)
        cls.by_coordinate = {
            (dependency.group, dependency.artifact): dependency for dependency in cls.project.dependencies
        }

    def test_declared_dependencies(self):
        self.assertIn(("org.apache.commons", "commons-text"), self.by_coordinate)
        self.assertIn(("commons-net", "commons-net"), self.by_coordinate)
        self.assertIn(("org.json", "json"), self.by_coordinate)

    def test_version_property_resolution(self):
        compress = self.by_coordinate[("org.apache.commons", "commons-compress")]
        self.assertEqual(compress.version, "1.25.0")
        self.assertEqual(compress.version_file, "build.gradle.kts")
        self.assertEqual(compress.version_line, 21)
        json_dep = self.by_coordinate[("org.json", "json")]
        self.assertEqual(json_dep.version, "20230227")
        self.assertEqual(json_dep.version_file, "gradle.properties")
        self.assertEqual(json_dep.version_line, 1)

    def test_multiline_add(self):
        commons_net = self.by_coordinate[("commons-net", "commons-net")]
        self.assertEqual(commons_net.line, 36)
        self.assertEqual(commons_net.scope, "implementation")

    def test_safe_control_not_flagged(self):
        from app.analysis.sca.engine import SCAAnalyzer

        findings = SCAAnalyzer(BASE_DIR / "training-main" / "vulnerability-database" / "vulnerabilities.json").analyze(
            SourceService(load_settings({"seed_templates": False})).resolve(
                {"kind": "path", "path": str(TRAINING)}
            )
        ).findings
        self.assertFalse(
            any(f.group == "org.apache.commons" and f.artifact == "commons-lang3" for f in findings)
        )


if __name__ == "__main__":
    unittest.main()


class SecretMaskingTests(unittest.TestCase):
    def test_mask_value_hides_value_completely(self):
        from app.crypto import mask_value

        self.assertEqual(mask_value("cg2secret6Qp"), "••••••")
        self.assertEqual(mask_value(""), "")
