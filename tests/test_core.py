from __future__ import annotations

from contextlib import redirect_stdout
import hashlib
import io
import json
from pathlib import Path
import tempfile
import unittest

from agent_tree_rl.cli import main as cli_main
from agent_tree_rl.config import ConfigurationError, Settings
from agent_tree_rl.engine import (
    PUCTSearch,
    PolicyValueModel,
    default_benchmark,
    default_scenario,
)
from agent_tree_rl.learner import OfflineLearner
from agent_tree_rl.metrics import Metrics
from agent_tree_rl.serde import (
    model_from_payload,
    model_to_payload,
    search_result_to_experience,
)


class CoreProductionTests(unittest.TestCase):
    def test_demo_is_one_command_and_labels_the_fixture_synthetic(self) -> None:
        output = io.StringIO()
        with redirect_stdout(output):
            status = cli_main(
                ["demo", "--simulations", "64", "--seed", "7", "--json"]
            )
        payload = json.loads(output.getvalue())
        self.assertEqual(0, status)
        self.assertTrue(payload["synthetic"])
        self.assertTrue(payload["feasible"])
        self.assertEqual(
            ["PROPOSE", "QUESTION", "ANSWER", "COMMIT"],
            [move["kind"] for move in payload["trajectory"]],
        )
        self.assertIn("no external agents", payload["notice"].lower())

    def test_settings_authenticate_hashed_tenant_token(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            token = "a-production-token-with-enough-entropy"
            token_file = root / "tokens.json"
            token_file.write_text(
                json.dumps(
                    {
                        hashlib.sha256(token.encode()).hexdigest(): {
                            "tenant_id": "tenant-a",
                            "roles": ["agent", "auditor"],
                            "subject_id": "core-test-subject",
                        }
                    }
                ),
                encoding="utf-8",
            )
            token_file.chmod(0o600)
            key_file = root / "keys.json"
            key_file.write_text("{}", encoding="utf-8")
            key_file.chmod(0o600)
            settings = Settings.from_env(
                {
                    "AGENT_TREE_RL_DATA_DIR": str(root),
                    "AGENT_TREE_RL_ADMIN_TOKEN_FILE": str(token_file),
                    "AGENT_TREE_RL_RECEIPT_KEYS_FILE": str(key_file),
                    "AGENT_TREE_RL_DATABASE": str(root / "db.sqlite3"),
                }
            )
            principal = settings.authenticate(token)
            self.assertIsNotNone(principal)
            self.assertEqual(principal.tenant_id, "tenant-a")
            self.assertIsNone(settings.authenticate("wrong"))

    def test_policy_artifact_round_trip_is_content_stable(self) -> None:
        learner = OfflineLearner()
        model = learner.train_challenger(PolicyValueModel(), episodes=3, simulations=64)
        payload = model_to_payload(model, family="family-a")
        restored = model_from_payload(payload)
        self.assertEqual(restored.model_version, model.model_version)
        self.assertEqual(restored.snapshot(), model.snapshot())

    def test_search_experience_is_json_serializable(self) -> None:
        scenario = default_scenario()
        benchmark = default_benchmark(scenario)
        result = PUCTSearch(scenario, benchmark, PolicyValueModel(), seed=7).run(64)
        payload = search_result_to_experience(
            result, tenant_id="tenant-a", family="family-a", run_id="run-1"
        )
        encoded = json.dumps(payload, sort_keys=True)
        self.assertIn(result.learning_receipt_hash, encoded)

    def test_challenger_passes_controlled_promotion_gates(self) -> None:
        learner = OfflineLearner()
        champion = PolicyValueModel()
        challenger = learner.train_challenger(champion)
        report = learner.promotion_report(champion, challenger)
        self.assertTrue(report.accepted, report.reasons)
        self.assertGreater(report.reward_delta, 0.0)
        self.assertLessEqual(
            report.challenger.hard_gate_failures,
            report.champion.hard_gate_failures,
        )

    def test_metrics_are_prometheus_escaped(self) -> None:
        metrics = Metrics()
        metrics.increment("requests_total", route='a"b', status="200")
        metrics.increment("requests_total", tenant="customer-secret")
        rendered = metrics.render()
        self.assertIn('route="a\\"b"', rendered)
        self.assertIn("agent_tree_rl_requests_total", rendered)
        self.assertNotIn("customer-secret", rendered)

    def test_unauthenticated_service_cannot_bind_all_interfaces(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ConfigurationError, "loopback"):
                Settings.from_env(
                    {
                        "AGENT_TREE_RL_DATA_DIR": str(root),
                        "AGENT_TREE_RL_HOST": "0.0.0.0",
                        "AGENT_TREE_RL_REQUIRE_AUTH": "false",
                    }
                )

    def test_public_evidence_allowlist_rejects_general_interpreters(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            with self.assertRaisesRegex(ConfigurationError, "forbidden"):
                Settings.from_env(
                    {
                        "AGENT_TREE_RL_DATA_DIR": str(root),
                        "AGENT_TREE_RL_HOST": "127.0.0.1",
                        "AGENT_TREE_RL_REQUIRE_AUTH": "false",
                        "AGENT_TREE_RL_ALLOWED_COMMANDS": "/usr/bin/python3",
                    }
                )


if __name__ == "__main__":
    unittest.main()
