.PHONY: install format lint typecheck security contracts policy-test test integration check helm terraform rego image run clean

CHART := deployments/helm/runtime-authorization-platform

install:
	uv sync

format:
	uv run black src tests
	uv run ruff check src tests --fix

lint:
	uv run ruff check src tests
	uv run black --check src tests

typecheck:
	uv run mypy

security:
	uv run python -m bandit -q -r src -c pyproject.toml

contracts:
	uv run python -m runtime_authorization_platform.contracts --check

policy-test:
	uv run authz-policy-test catalog policies/actions.yaml
	uv run authz-policy-test test \
	  policies/runtime-authorization.yaml policies/tests/runtime-authorization.tests.yaml \
	  policies/service-access.yaml policies/tests/service-access.tests.yaml

test:
	uv run pytest

integration:
	uv run pytest tests/integration -m integration --no-cov

check: lint typecheck security contracts policy-test test

rego:
	uv run authz-policy-test rego policies/runtime-authorization.yaml

helm:
	helm lint $(CHART) -f $(CHART)/ci/test-values.yaml
	! helm template authz $(CHART) > /dev/null 2>&1

terraform:
	terraform fmt -recursive -check deployments/terraform
	for c in aws azure gcp; do terraform -chdir=deployments/terraform/$$c init -backend=false -input=false && terraform -chdir=deployments/terraform/$$c validate; done

image:
	docker build -t runtime-authorization-platform:dev .

run:
	docker compose up --build

clean:
	rm -rf dist build .pytest_cache .mypy_cache .ruff_cache .coverage coverage.xml
