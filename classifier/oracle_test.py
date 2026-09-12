import unittest

from oracle import (
    GLUE_AXES,
    SECURITY_AXES,
    SMOKE_AXES,
    classify_failure,
    compare_observations,
    delta_divergence,
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
            "coredns_fwd": {
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
            "coredns_fwd": {
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
            "coredns_fwd": {
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
            "coredns_fwd": {
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

    def test_all_null_flagged_when_neither_side_responds(self):
        """Both stand-ins dead: D(p)=0 must not read as agreement (Reviewer X item 4)."""
        obs = {
            "unbound": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "timeout",
            },
            "coredns_fwd": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "dig exit 9",
            },
        }
        result = compare_observations(obs, axes=SECURITY_AXES)
        self.assertTrue(result["all_null"])

    def test_all_null_false_when_one_side_responds(self):
        obs = {
            "unbound": {
                "rcode": "SERVFAIL",
                "answers": [],
                "aa": False,
                "ra": True,
                "error": None,
            },
            "dnsmasq": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "dig exit 9",
            },
        }
        result = compare_observations(obs, axes=SECURITY_AXES)
        self.assertFalse(result["all_null"])

    def test_hang_or_crash_distinguishes_failure_classes(self):
        """Timeout vs. hard dig-exit both being truthy `error` must not collapse to
        'agreement' (Reviewer X item 5): REFUSED-vs-timeout is a real divergence."""
        self.assertNotEqual(classify_failure("timeout"), classify_failure("dig exit 9"))
        obs = {
            "unbound": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "timeout",
            },
            "coredns_fwd": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "dig exit 9",
            },
        }
        result = compare_observations(obs, axes=SECURITY_AXES)
        self.assertEqual(result["divergence_count"], 1)
        self.assertEqual(result["divergences"][0]["axis"], "hang_or_crash")

    def test_hang_or_crash_same_class_different_detail_agrees(self):
        """Same failure class with different detail strings must still agree."""
        self.assertEqual(classify_failure("dig exit 1"), classify_failure("dig exit 9"))
        obs = {
            "unbound": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "dig exit 1",
            },
            "coredns_fwd": {
                "rcode": None,
                "answers": [],
                "aa": None,
                "ra": None,
                "error": "dig exit 9",
            },
        }
        result = compare_observations(obs, axes=SECURITY_AXES)
        self.assertEqual(result["divergence_count"], 0)

    def test_delta_divergence_matches_published_glue_result(self):
        """Regression: August glue pin's ΔD(p)=1 on ADDITIONAL (Table IV) must not change."""
        baseline = {
            "dnsmasq": {"rcode": "NOERROR", "answers": ["203.0.113.10"], "aa": True, "ra": True, "error": None, "additional": [], "glue_cache_accept": False},
            "unbound": {"rcode": "NOERROR", "answers": ["203.0.113.10"], "aa": False, "ra": True, "error": None, "additional": [], "glue_cache_accept": False},
        }
        pin = {
            "dnsmasq": {"rcode": "NOERROR", "answers": ["203.0.113.20"], "aa": True, "ra": True, "error": None, "additional": ["ns.evil.test|198.51.100.66"], "glue_cache_accept": False},
            "unbound": {"rcode": "NOERROR", "answers": ["203.0.113.20"], "aa": False, "ra": True, "error": None, "additional": [], "glue_cache_accept": False},
        }
        baseline_result = compare_observations(baseline, axes=GLUE_AXES)
        pin_result = compare_observations(pin, axes=GLUE_AXES)
        self.assertEqual(baseline_result["divergence_count"], 1)
        self.assertEqual(pin_result["divergence_count"], 2)
        delta = delta_divergence(pin_result, baseline_result)
        self.assertEqual(delta["delta_divergence_count"], 1)
        self.assertEqual(delta["delta_divergences"][0]["axis"], "additional")
        self.assertEqual(delta["baseline_axes"], ["aa"])

    def test_delta_divergence_catches_baseline_polarity_flip(self):
        """A baseline axis whose divergent VALUES reverse under the adversary is a new
        finding — axis-name-only subtraction would wrongly zero it out (Reviewer X item 10)."""
        baseline = {
            "r1": {"rcode": "NOERROR", "answers": ["a"], "aa": False, "ra": True, "error": None},
            "r2": {"rcode": "NOERROR", "answers": ["a"], "aa": True, "ra": True, "error": None},
        }
        pin = {
            "r1": {"rcode": "NOERROR", "answers": ["a"], "aa": True, "ra": True, "error": None},
            "r2": {"rcode": "NOERROR", "answers": ["a"], "aa": False, "ra": True, "error": None},
        }
        baseline_result = compare_observations(baseline, axes=SECURITY_AXES)
        pin_result = compare_observations(pin, axes=SECURITY_AXES)
        self.assertEqual(baseline_result["divergence_count"], 1)
        self.assertEqual(pin_result["divergence_count"], 1)
        delta = delta_divergence(pin_result, baseline_result)
        self.assertEqual(delta["delta_divergence_count"], 1, "polarity flip must not be masked")
        self.assertEqual(delta["delta_divergences"][0]["axis"], "aa")

    def test_null_aware_gates_header_axes(self):
        """SERVFAIL vs dig timeout: only hang_or_crash enters null-aware D(p)."""
        obs = {
            "unbound": {
                "rcode": "SERVFAIL",
                "answers": [],
                "aa": False,
                "ra": True,
                "error": None,
            },
            "dnsmasq": {
                "rcode": None,
                "answers": [],
                "aa": False,
                "ra": False,
                "error": "dig exit 9",
            },
        }
        gated = compare_observations(obs, axes=SECURITY_AXES, null_aware=True)
        self.assertEqual(gated["divergence_count"], 1)
        self.assertEqual(gated["divergences"][0]["axis"], "hang_or_crash")
        ungated = compare_observations(obs, axes=SECURITY_AXES, null_aware=False)
        self.assertGreaterEqual(ungated["divergence_count"], 2)
        self.assertTrue(any(d["axis"] == "rcode" for d in ungated["divergences"]))


if __name__ == "__main__":
    unittest.main()
