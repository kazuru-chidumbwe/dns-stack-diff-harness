import unittest

from oracle import SMOKE_AXES, compare_observations, normalize_answers


class OracleTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(
            normalize_answers(["203.0.113.10.", "203.0.113.10"]),
            ["203.0.113.10", "203.0.113.10"],
        )

    def test_agree(self):
        obs = {
            "unbound": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.10"],
                "aa": False,
                "ra": True,
                "error": None,
            },
            "dnsmasq": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.10"],
                "aa": False,
                "ra": True,
                "error": None,
            },
        }
        result = compare_observations(obs)
        self.assertEqual(result["divergence_count"], 0)
        self.assertEqual(result["class_hint"], "pass")

    def test_smoke_ignores_flag_only_divergence(self):
        obs = {
            "unbound": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.10"],
                "aa": False,
                "ra": True,
                "error": None,
            },
            "dnsmasq": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.10"],
                "aa": True,
                "ra": False,
                "error": None,
            },
        }
        smoke = compare_observations(obs, axes=SMOKE_AXES)
        self.assertEqual(smoke["divergence_count"], 0)
        full = compare_observations(obs)
        self.assertGreaterEqual(full["divergence_count"], 1)

    def test_rcode_divergence(self):
        obs = {
            "unbound": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.10"],
                "aa": False,
                "ra": True,
                "error": None,
            },
            "dnsmasq": {
                "rcode": "SERVFAIL",
                "answers": [],
                "aa": False,
                "ra": True,
                "error": None,
            },
        }
        result = compare_observations(obs, axes=SMOKE_AXES)
        self.assertGreaterEqual(result["divergence_count"], 1)
        self.assertTrue(any(d["axis"] == "rcode" for d in result["divergences"]))


if __name__ == "__main__":
    unittest.main()
