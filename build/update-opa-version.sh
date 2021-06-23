#!/usr/bin/env bash
# Script to update version references following an OPA version bump

set +e
set -x

FILES=(README.md quick_start.yaml examples/istio/quick_start.yaml)

# e.g. 0.29.4 (no 'v' prefix)
tag=$(go list -m -f '{{ .Version }}' github.com/open-policy-agent/opa | cut -c 2-)

# update plugin image version in README
sed -i.bak "s/openpolicyagent\/opa:.*/openpolicyagent\/opa:$tag-envoy/" README.md && rm README.md.bak

# update plugin image version in quick_start.yaml for Envoy
sed -i.bak "s/image: openpolicyagent\/opa:.*/image: openpolicyagent\/opa:$tag-envoy/" quick_start.yaml && rm quick_start.yaml.bak

# update plugin image version in quick_start.yaml for the Istio deployment example
sed -i.bak "/opa_container/{N;s/openpolicyagent\/opa:.*/openpolicyagent\/opa:$tag-istio\"\,/;}" examples/istio/quick_start.yaml && rm examples/istio/quick_start.yaml.bak
sed -i.bak "s/image: openpolicyagent\/opa:.*/image: openpolicyagent\/opa:$tag/" examples/istio/quick_start.yaml && rm examples/istio/quick_start.yaml.bak

for file in "${FILES[@]}"; do
  git add "$file"
done

if [[ -z "$(git diff --name-only --cached)" ]]; then
  echo "No version changes to commit!"
  exit 1
fi

git commit -m "examples: update OPA version tags ($tag)"

echo
echo "Committed changes for files:"
git diff-tree --no-commit-id --name-only -r HEAD
echo
