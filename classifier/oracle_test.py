import unittest

from oracle import (
    GLUE_AXES,
    SMOKE_AXES,
    compare_observations,
    normalize_additional,
    normalize_answers,
)


class OracleTests(unittest.TestCase):
    def test_normalize(self):
        self.assertEqual(
            normalize_answers(["203.0.113.10.", "203.0.113.10"]),
            ["203.0.113.10", "203.0.113.10"],
        )

    def test_normalize_additional(self):
        self.assertEqual(
            normalize_additional(["Ns.Evil.Test.|198.51.100.66", "ns.evil.test.|198.51.100.66"]),
            ["ns.evil.test|198.51.100.66", "ns.evil.test|198.51.100.66"],
        )

    def test_glue_cache_accept_divergence(self):
        obs = {
            "unbound": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.20"],
                "additional": [],
                "aa": False,
                "ra": True,
                "error": None,
                "glue_cache_accept": False,
            },
            "dnsmasq": {
                "rcode": "NOERROR",
                "answers": ["203.0.113.20"],
                "additional": [],
                "aa": True,
                "ra": True,
                "error": None,
                "glue_cache_accept": True,
            },
        }
        result = compare_observations(obs, axes=GLUE_AXES)
        self.assertTrue(any(d["axis"] == "glue_cache_accept" for d in result["divergences"]))
        self.assertTrue(any(d["axis"] == "aa" for d in result["divergences"]))

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
