"""sec_check_gui 규칙 단위 테스트.

실행: python -m unittest test_sec_check -v
"""

import unittest

import sec_check_gui as m


def base(**over):
    d = {
        "isAdmin": True,
        "host": "TEST",
        "osCaption": "Windows 11 Pro",
        "osBuild": "26100",
        "uac": 1,
        "autologon": "0",
        "users": [{"name": "me", "enabled": True, "passwordRequired": True, "sid": "S-1-5-21-1-2-3-1001"}],
        "bitlockerSupported": True,
        "bitlocker": [{"mount": "C:", "protection": "On"}],
        "smb1": False,
        "smbSigning": True,
        "rdpDeny": 1,
        "firewall": [{"name": "Domain", "enabled": True}, {"name": "Private", "enabled": True}, {"name": "Public", "enabled": True}],
        "llmnr": 0,
        "defender": {"rtp": True, "av": True, "sigAge": 0},
        "defenderExclusions": [],
        "lastHotfix": "2026-09-23",
        "lastHotfixId": "KB1",
        "pendingReboot": False,
        "listenPorts": [135, 445],
    }
    d.update(over)
    return d


def one(check, **over):
    return check(base(**over))


class TestNoneHandling(unittest.TestCase):
    def test_uac_none_unknown(self):
        self.assertEqual(one(m.check_uac, uac=None).status, "확인불가")

    def test_uac_off_is_risk(self):
        r = one(m.check_uac, uac=0)
        self.assertEqual((r.status, r.severity), ("위험", "높음"))

    def test_smb1_none_unknown(self):
        self.assertEqual(one(m.check_smb1, smb1=None).status, "확인불가")

    def test_smb1_true_is_risk(self):
        self.assertEqual(one(m.check_smb1, smb1=True).status, "위험")

    def test_smb_signing_none_unknown(self):
        self.assertEqual(one(m.check_smb_signing, smbSigning=None).status, "확인불가")

    def test_smb_signing_false_is_warn(self):
        self.assertEqual(one(m.check_smb_signing, smbSigning=False).status, "주의")

    def test_rdp_none_unknown(self):
        self.assertEqual(one(m.check_rdp, rdpDeny=None).status, "확인불가")

    def test_sig_age_none_unknown(self):
        self.assertEqual(one(m.check_signature_age, defender={}).status, "확인불가")

    def test_patch_none_unknown(self):
        self.assertEqual(one(m.check_patch, lastHotfix=None).status, "확인불가")

    def test_firewall_empty_unknown(self):
        self.assertEqual(one(m.check_firewall, firewall=[]).status, "확인불가")


class TestSidAccounts(unittest.TestCase):
    def test_guest_by_sid_enabled_risk(self):
        users = [{"name": "무명계정", "enabled": True, "passwordRequired": True, "sid": "S-1-5-21-1-2-3-501"}]
        self.assertEqual(one(m.check_guest, users=users).status, "위험")

    def test_guest_by_sid_disabled_ok(self):
        users = [{"name": "Guest", "enabled": False, "passwordRequired": False, "sid": "S-1-5-21-1-2-3-501"}]
        self.assertEqual(one(m.check_guest, users=users).status, "양호")

    def test_builtin_admin_enabled_warn(self):
        users = [{"name": "바뀐이름", "enabled": True, "passwordRequired": True, "sid": "S-1-5-21-1-2-3-500"}]
        self.assertEqual(one(m.check_builtin_admin, users=users).status, "주의")

    def test_blank_password_risk(self):
        users = [{"name": "me", "enabled": True, "passwordRequired": False, "sid": "S-1-5-21-1-2-3-1001"}]
        self.assertEqual(one(m.check_password_required, users=users).status, "위험")


class TestAdminGated(unittest.TestCase):
    def test_bitlocker_non_admin_unknown(self):
        self.assertEqual(one(m.check_bitlocker, isAdmin=False, bitlockerSupported=None).status, "확인불가")

    def test_exclusions_non_admin_unknown(self):
        self.assertEqual(one(m.check_exclusions, isAdmin=False).status, "확인불가")

    def test_exclusions_set_warn(self):
        self.assertEqual(one(m.check_exclusions, defenderExclusions=["C:\\temp"]).status, "주의")


class TestBaseline(unittest.TestCase):
    def test_all_ok_is_100_A(self):
        results = m.run_checks(base())
        rate, grade, counts = m.baseline(results)
        self.assertEqual(rate, 100)
        self.assertEqual(grade, "A")
        self.assertEqual(counts["위험"], 0)

    def test_info_excluded_from_rate(self):
        results = m.run_checks(base())
        self.assertEqual(m.baseline(results)[2]["정보"], 1)  # only the ports row is informational

    def test_risk_drops_grade(self):
        results = m.run_checks(base(uac=0, smb1=True))
        rate, grade, _ = m.baseline(results)
        self.assertLess(rate, 90)
        self.assertNotEqual(grade, "A")


class TestEvaluation(unittest.TestCase):
    def test_risk_has_why_and_steps(self):
        r = one(m.check_uac, uac=0)
        self.assertTrue(r.why)
        self.assertGreaterEqual(len(r.steps), 2)

    def test_blank_password_has_steps(self):
        users = [{"name": "me", "enabled": True, "passwordRequired": False, "sid": "S-1-5-21-1-2-3-1001"}]
        r = one(m.check_password_required, users=users)
        self.assertTrue(r.why)
        self.assertTrue(r.steps)

    def test_assess_reports_issue(self):
        text = m.assess(m.run_checks(base(uac=0)))
        self.assertIn("종합 평가", text)
        self.assertIn("UAC", text)

    def test_assess_all_ok_clean(self):
        text = m.assess(m.run_checks(base()))
        self.assertIn("통과율", text)
        self.assertIn("없", text)


if __name__ == "__main__":
    unittest.main()