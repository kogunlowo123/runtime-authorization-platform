# Runbook: policy change

Policy changes follow four-eyes: an author submits, a different approver
activates. The platform refuses a version whose tests fail or that has a rule
no test case decides.

## 1. Author and test locally

Edit `policies/runtime-authorization.yaml` and add cases to
`policies/tests/runtime-authorization.tests.yaml` for every new or changed
rule, then:

```bash
make policy-test     # authz-policy-test: cases and rule coverage
make rego            # optional: inspect the Rego equivalent
```

Open a pull request; CODEOWNERS review `policies/`. CI runs the same policy
tests, the full suite and OPA parity.

## 2. Dry run against the running platform

```bash
python - <<'PY' > submission.json
import json, yaml
print(json.dumps({
    "policy": yaml.safe_load(open("policies/runtime-authorization.yaml")),
    "tests": yaml.safe_load(open("policies/tests/runtime-authorization.tests.yaml"))["cases"],
}))
PY
curl -s -X POST "$AUTHZ/v1/policies/test" -H "Authorization: Bearer $AUTHOR_TOKEN" \
  -H 'Content-Type: application/json' --data @submission.json | jq '{ok, failed, uncovered_rules}'
```

## 3. Submit

```bash
curl -s -X POST "$AUTHZ/v1/policies" -H "Authorization: Bearer $AUTHOR_TOKEN" \
  -H 'Content-Type: application/json' --data @submission.json | jq '{version_id, digest, status}'
```

## 4. Approve and activate (different person)

```bash
curl -s -X POST -H "Authorization: Bearer $APPROVER_TOKEN" "$AUTHZ/v1/policies/<version_id>/activate"
```

The `AuthzPolicyActivated` alert fires on every activation; confirm the
digest matches the reviewed pull request. Watch the deny ratio for 30
minutes; roll back by re-activating the previous version if it moves
unexpectedly.
