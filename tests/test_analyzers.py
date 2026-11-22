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

TRAINING = BASE_DIR / "training-main"


class AnalyzerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.settings = load_settings({"seed_templates": False})
        cls.tree = SourceService(cls.settings).resolve({"kind": "default"})
        cls.findings = []
        for analyzer in (
            SecretAnalyzer(),
            SCAAnalyzer(cls.settings.vulnerability_db_path),
            SASTAnalyzer(),
        ):
            cls.findings.extend(analyzer.analyze(cls.tree).findings)

    def test_expected_findings(self):
        self.assertEqual(len(self.findings), 9)
        self.assertEqual(
            {finding.category for finding in self.findings},
            {"SECRET", "SCA", "SAST"},
        )

    def test_secret_findings(self):
        secrets = {
            (finding.path, finding.class_name, finding.line)
            for finding in self.findings
            if finding.category == "SECRET"
        }
        self.assertEqual(
            secrets,
            {
                ("src/main/kotlin/lab/pavilion/gateway/AvailabilityRequest.kt", "api-key", 7),
                ("src/main/resources/application-lab.yml", "configuration-token", 4),
                ("src/main/resources/application.properties", "connection-string", 5),
            },
        )

    def test_sca_findings(self):
        sca = [finding for finding in self.findings if finding.category == "SCA"]
        self.assertEqual(len(sca), 5)
        coordinates = {(finding.group, finding.artifact, finding.version) for finding in sca}
        self.assertEqual(
            coordinates,
            {
                ("org.apache.commons", "commons-configuration2", "2.7"),
                ("net.minidev", "json-smart", "2.4.8"),
                ("com.google.code.gson", "gson", "2.8.8"),
                ("org.apache.commons", "commons-lang3", "3.17.0"),
                ("org.apache.httpcomponents", "httpclient", "4.5.12"),
            },
        )
        self.assertTrue(all(finding.advisory_id for finding in sca))
        self.assertFalse(any(finding.artifact == "commons-text" for finding in sca))

    def test_sast_finding(self):
        sast = [finding for finding in self.findings if finding.category == "SAST"]
        self.assertEqual(len(sast), 1)
        self.assertEqual(sast[0].class_name, "tls-verification")
        self.assertEqual(sast[0].path, "src/main/kotlin/lab/pavilion/gateway/CalendarHttpClient.kt")
        self.assertEqual(sast[0].line, 16)


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
        self.assertIn(("org.apache.commons", "commons-configuration2"), self.by_coordinate)
        self.assertIn(("net.minidev", "json-smart"), self.by_coordinate)
        self.assertIn(("com.google.code.gson", "gson"), self.by_coordinate)
        self.assertIn(("org.apache.commons", "commons-lang3"), self.by_coordinate)
        self.assertIn(("org.apache.httpcomponents", "httpclient"), self.by_coordinate)
        self.assertIn(("org.jsoup", "jsoup"), self.by_coordinate)

    def test_literal_versions(self):
        configuration = self.by_coordinate[("org.apache.commons", "commons-configuration2")]
        self.assertEqual(configuration.version, "2.7")
        self.assertEqual(configuration.line, 32)
        smart = self.by_coordinate[("net.minidev", "json-smart")]
        self.assertEqual(smart.version, "2.4.8")
        self.assertEqual(smart.line, 33)
        jsoup = self.by_coordinate[("org.jsoup", "jsoup")]
        self.assertEqual(jsoup.version, "1.24.1")

    def test_multiline_dependency(self):
        gson = self.by_coordinate[("com.google.code.gson", "gson")]
        self.assertEqual(gson.version, "2.8.8")
        self.assertEqual(gson.line, 34)
        self.assertEqual(gson.scope, "implementation")

    def test_variable_and_strictly_versions(self):
        lang = self.by_coordinate[("org.apache.commons", "commons-lang3")]
        self.assertEqual(lang.version, "3.17.0")
        self.assertEqual(lang.line, 39)
        httpclient = self.by_coordinate[("org.apache.httpcomponents", "httpclient")]
        self.assertEqual(httpclient.version, "4.5.12")
        self.assertEqual(httpclient.line, 40)

    def test_safe_control_not_flagged(self):
        from app.analysis.sca.engine import SCAAnalyzer

        settings = load_settings({"seed_templates": False})
        findings = SCAAnalyzer(settings.vulnerability_db_path).analyze(
            SourceService(settings).resolve({"kind": "default"})
        ).findings
        self.assertFalse(any(f.artifact == "jsoup" for f in findings))

if __name__ == "__main__":
    unittest.main()


class SecretMaskingTests(unittest.TestCase):
    def test_mask_value_hides_value_completely(self):
        from app.crypto import mask_value

        self.assertEqual(mask_value("cg2secret6Qp"), "••••••")
        self.assertEqual(mask_value(""), "")
