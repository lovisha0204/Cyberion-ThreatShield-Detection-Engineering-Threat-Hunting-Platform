#!/usr/bin/env python3
"""
Unit Test Suite for Cyberion Defense Labs Detection Content
Runs automated integrity assertions across all rules, coverage layers, and telemetry.
"""

import os
import sys
import json
import glob
import uuid
import unittest
import yaml

# Add tools to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(BASE_DIR, "tools"))
from harness import SigmaRuleEvaluator

class TestDetectionRuleIntegrity(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.rules_dir = os.path.join(BASE_DIR, "rules")
        cls.data_dir = os.path.join(BASE_DIR, "data")
        cls.coverage_file = os.path.join(BASE_DIR, "coverage", "cyberion_attck_navigator_layer.json")
        cls.evaluator = SigmaRuleEvaluator(cls.rules_dir, cls.data_dir)
        cls.evaluator.load_telemetry()
        cls.rules = cls.evaluator.load_and_validate_rules()

    def test_minimum_rule_count(self):
        """PRD requires 15+ Sigma rules."""
        self.assertGreaterEqual(len(self.rules), 15, "Rule count must be at least 15")

    def test_correlation_rule_count(self):
        """PRD requires at least 3 correlation rules."""
        corr_rules = [r for r in self.rules if r.get("action") == "correlation"]
        self.assertGreaterEqual(len(corr_rules), 3, "Must have at least 3 correlation rules")

    def test_mandatory_fields(self):
        """Verify each rule contains all required PRD metadata fields."""
        required = ["title", "id", "status", "description", "references", "author", "date", "tags", "logsource", "detection", "falsepositives", "level", "rational"]
        for rule in self.rules:
            for field in required:
                self.assertIn(field, rule, f"Rule {rule.get('title')} missing '{field}'")

    def test_valid_uuid(self):
        """Verify each rule ID is a valid UUIDv4."""
        for rule in self.rules:
            rule_id = rule.get("id")
            try:
                parsed_uuid = uuid.UUID(str(rule_id))
                self.assertEqual(str(parsed_uuid), str(rule_id).lower(), f"Invalid UUID: {rule_id}")
            except ValueError:
                self.fail(f"Invalid UUID in rule {rule.get('title')}: {rule_id}")

    def test_mitre_attack_tags(self):
        """Verify each rule is tagged with a valid MITRE ATT&CK technique ID."""
        for rule in self.rules:
            tags = rule.get("tags", [])
            has_technique = any(t.startswith("attack.t") or t.startswith("attack.T") for t in tags)
            self.assertTrue(has_technique, f"Rule {rule.get('title')} missing attack.tXXXX tag")

    def test_all_rules_trigger_on_attack_telemetry(self):
        """PRD requires 100% of submitted rules tested against actual log data."""
        for rule in self.rules:
            is_correlation = rule.get("action") == "correlation"
            if is_correlation:
                hits = self.evaluator.evaluate_correlation_rule(rule, self.evaluator.attack_events)
            else:
                hits = [ev for ev in self.evaluator.attack_events if self.evaluator.evaluate_rule_against_event(rule, ev)]
            self.assertGreater(len(hits), 0, f"Rule {rule.get('_filename')} did not match any attack telemetry events!")

    def test_benign_telemetry_false_positive_resilience(self):
        """Verify that benign enterprise baseline does not produce false positives."""
        fp_hits = []
        for rule in self.rules:
            is_correlation = rule.get("action") == "correlation"
            if is_correlation:
                hits = self.evaluator.evaluate_correlation_rule(rule, self.evaluator.benign_events)
            else:
                hits = [ev for ev in self.evaluator.benign_events if self.evaluator.evaluate_rule_against_event(rule, ev)]
            if hits:
                fp_hits.append((rule.get("_filename"), [h.get("_id") for h in hits]))
        self.assertEqual(len(fp_hits), 0, f"False positives detected: {fp_hits}")

    def test_navigator_layer_validity(self):
        """Verify MITRE ATT&CK Navigator layer is valid JSON and contains required keys."""
        self.assertTrue(os.path.exists(self.coverage_file), "Missing ATT&CK Navigator layer JSON")
        with open(self.coverage_file, "r", encoding="utf-8") as f:
            layer = json.load(f)
        self.assertIn("techniques", layer)
        self.assertGreaterEqual(len(layer["techniques"]), 20, "Navigator layer must cover at least 20 techniques")

if __name__ == "__main__":
    unittest.main(verbosity=2)
