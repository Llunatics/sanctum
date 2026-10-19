"""Unit tests for sanctum.generator — validation and JSON extraction."""
import unittest

from sanctum.generator import _extract_json_array, _validate, load_seed_cases


def _case(**kw):
    d = {"id": "T01", "category": "injection", "title": "t",
         "payload": "p", "expected_safe": "safe", "severity": "high"}
    d.update(kw)
    return d


class TestValidate(unittest.TestCase):
    def test_good_cases_pass(self):
        out = _validate([_case(), _case(id="T02")])
        self.assertEqual([c["id"] for c in out], ["T01", "T02"])

    def test_extra_keys_stripped(self):
        out = _validate([_case(junk="x")])
        self.assertNotIn("junk", out[0])

    def test_missing_key_rejected(self):
        bad = _case()
        del bad["payload"]
        with self.assertRaises(ValueError):
            _validate([bad])

    def test_bad_severity_rejected(self):
        with self.assertRaises(ValueError):
            _validate([_case(severity="low")])

    def test_duplicate_ids_rejected(self):
        with self.assertRaises(ValueError):
            _validate([_case(), _case()])

    def test_non_dict_rejected(self):
        with self.assertRaises(ValueError):
            _validate(["nope"])

    def test_empty_rejected_by_cli(self):
        # _validate([]) returns []; the CLI guards emptiness separately.
        self.assertEqual(_validate([]), [])


class TestExtractJsonArray(unittest.TestCase):
    def test_plain_array(self):
        self.assertEqual(_extract_json_array('[{"a":1}]'), [{"a": 1}])

    def test_prose_around_array(self):
        txt = 'Here you go:\n[{"a":1}]\nHope this helps [Note: x].'
        self.assertEqual(_extract_json_array(txt), [{"a": 1}])

    def test_no_array(self):
        with self.assertRaises(ValueError):
            _extract_json_array("no brackets here")

    def test_not_an_array(self):
        with self.assertRaises(ValueError):
            _extract_json_array('{"a": 1}')


class TestSeedCases(unittest.TestCase):
    def test_seed_cases_load_and_validate(self):
        cases = load_seed_cases()
        self.assertEqual(len(cases), 20)
        # The bundled seeds must pass the same validation as LLM output.
        _validate(cases)

    def test_category_filter(self):
        cats = {c["category"] for c in load_seed_cases()}
        self.assertTrue(cats)
        for cat in cats:
            sub = load_seed_cases(category=cat)
            self.assertTrue(sub)
            self.assertTrue(all(c["category"] == cat for c in sub))


if __name__ == "__main__":
    unittest.main()
