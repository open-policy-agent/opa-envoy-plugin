# Release Process

1. Check the latest version of the pushed OPA-Envoy image in the `Checks` GHA workflow on the `main` branch. Look for a `docker buildx build` entry (there are several) in the `Push Latest Release` job. The release version format is `<opa_version>-envoy-<#number of commits from last vendored OPA>`, e.g. `1.3.0-envoy-1`.
2. Now that we know the release version, draft a new release with `v<version>` (e.g. `v1.3.0-envoy-1`) as the new tag and as the release title.
3. Then press `Generate release notes`. Make modifications as needed.
4. If everything looks good, click `Publish Release`.
  This will trigger a GHA that will attach the assets to the release. You can track progress in the `Post Tag` GHA workflow.
