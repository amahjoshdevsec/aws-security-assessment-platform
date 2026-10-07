import sys
import unittest
from pathlib import Path

sys.path.insert(
    0, str(Path(__file__).resolve().parents[1] / "scripts")
)

import scan


class ScopeExclusionTests(unittest.TestCase):
    def entry(self):
        return {
            "level": "ERROR",
            "module": "kms_service",
            "message": (
                "us-east-1 -- ClientError:56 -- An error occurred "
                "(AccessDeniedException) when calling the DescribeKey "
                "operation: User: arn:aws:sts::214745599312:"
                "assumed-role/ProwlerAudit/prowler-test "
                "is not authorized to perform: kms:DescribeKey "
                f"on resource: {scan.EXCLUDED_KMS_ARN} "
                "because no resource-based policy allows the "
                "kms:DescribeKey action"
            ),
        }

    def test_exact_known_denial_is_accepted(self):
        self.assertTrue(
            scan.expected_kms_error(
                self.entry(), scan.LAB_ACCOUNT, scan.LAB_REGION
            )
        )

    def test_other_key_is_rejected(self):
        entry = self.entry()
        entry["message"] = entry["message"].replace(
            scan.EXCLUDED_KMS_ID,
            "00000000-0000-0000-0000-000000000000",
        )
        self.assertFalse(
            scan.expected_kms_error(
                entry, scan.LAB_ACCOUNT, scan.LAB_REGION
            )
        )

    def test_other_account_or_region_is_rejected(self):
        for account, region in [
            ("111111111111", "us-east-1"),
            (scan.LAB_ACCOUNT, "us-west-2"),
        ]:
            self.assertFalse(
                scan.expected_kms_error(self.entry(), account, region)
            )
            self.assertEqual(scan.scope_exclusions(account, region), [])

    def test_other_operation_is_rejected(self):
        entry = self.entry()
        entry["message"] = entry["message"].replace(
            "DescribeKey", "GetKeyPolicy"
        )
        self.assertFalse(
            scan.expected_kms_error(
                entry, scan.LAB_ACCOUNT, scan.LAB_REGION
            )
        )

        