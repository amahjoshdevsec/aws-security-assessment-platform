# Original single-account Prowler Docker lab

This directory preserves the original walkthrough's scripts, Terraform, mutelist, Docker overrides and technical notes. It is a historical learning example. Use the [enterprise platform](../../README.md) for centralized ongoing assessments.

The source snapshot did not include its referenced README or `.prowler-version`; this index and the 5.38.0 version pin restore entry points. Run legacy commands from this directory so their relative paths resolve:

```bash
cd examples/local-server
make help
make setup
make secrets
make preflight
make up
```

Review [IAM setup](docs/aws-iam-setup.md), [Terraform notes](docs/terraform.md), [learning notes](docs/learn.md), and [troubleshooting](docs/troubleshooting.md) before acting. Historical screenshots/README anchors mentioned in the original notes may not exist in the source snapshot.

The legacy Terraform defaults to an IAM user with a permanent access key stored in state. The legacy additions policy includes a Security Hub write action; historical blanket read-only statements are inaccurate. The legacy mutelist includes broad lab-specific acceptance. None of these defaults are used by the enterprise workflows. Do not reuse them as production controls.

The original docs contain historical live-account verification and destructive recovery/teardown procedures. Those observations are preserved, not independently revalidated. The enterprise update neither runs those procedures nor modifies existing AWS resources.
