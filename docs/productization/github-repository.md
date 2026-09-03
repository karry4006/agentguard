# GitHub repository preparation

The owner-approved Phase 2 target is a private repository named agentguard.
The initial branch remains the current local primary branch until the first
push establishes the default branch.

After creation, verify the authenticated owner, repository name, remote URL,
and PRIVATE visibility before pushing. Enable GitHub Private Vulnerability
Reporting, Dependabot alerts, the dependency graph, secret scanning, and push
protection wherever the account and repository configuration supports them.
If a capability is unavailable, record
UNAVAILABLE_ON_CURRENT_GITHUB_CONFIGURATION rather than claiming it is on.

Configure branch protection only after the required CI check names have run
successfully. The intended policy is pull requests for mainline changes,
required passing CI, no force pushes, and no branch deletion. Do not require
signed commits without a separate owner decision.
