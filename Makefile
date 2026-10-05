.DEFAULT_GOAL := help
SHELL := /bin/bash
TF_ROOTS := terraform/security-tooling terraform/member-account
.PHONY: help test tf-init tf-check validate matrix mutelist container-check
help:
	@echo "Enterprise Prowler: test | tf-init | tf-check | validate | matrix | mutelist"
	@echo "Deployment is manual; see docs/terraform.md. Legacy Docker lab: examples/local-server."
test:
	python3 -m compileall -q scripts tests
	python3 -m unittest discover -s tests -v
	python3 scripts/governance.py validate
	python3 scripts/check_docs.py
	@for f in examples/local-server/scripts/*.sh; do bash -n "$$f" || exit 1; done
tf-init:
	@for root in $(TF_ROOTS); do terraform -chdir="$$root" init -backend=false -input=false -lockfile=readonly || exit 1; done
tf-check:
	terraform fmt -check -recursive terraform
	@for root in $(TF_ROOTS); do terraform -chdir="$$root" validate || exit 1; done
validate: test tf-check
matrix:
	python3 scripts/governance.py matrix
mutelist:
	python3 scripts/governance.py compile

container-check:
	mkdir -p build/container-smoke
	chmod 770 build/container-smoke
	docker run --rm --network none --user 1000:1000 --group-add "$$(id -g)" \
	  --cap-drop=ALL --security-opt=no-new-privileges -e HOME=/tmp \
	  -v "$(CURDIR):/project:ro" -v "$(CURDIR)/build/container-smoke:/reports" \
	  --entrypoint /home/prowler/.venv/bin/python "$$(cat .prowler-image)" /project/tests/container_contract.py
