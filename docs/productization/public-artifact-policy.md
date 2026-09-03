# Public artifact policy

Phase 1 prepares local release inputs but performs no publication.

## Candidates for public review

High-level README and usage documentation, source and SDK code, selected
examples, Compose and initialization files, package metadata, and a reviewed
change log can be public after owner approval. A release manifest or SBOM may
be published only after removing machine paths, local usernames, internal
URLs, tenant identifiers, and other operational metadata.

## Internal by default

Raw acceptance evidence, live logs, tenant and key identifiers, database
dumps, temporary directories, Docker caches, private keys, secret files,
internal Scout output, and sealed V20 closure artifacts are internal unless a
separate owner review explicitly approves a sanitized derivative.

Do not mutate sealed V19 or V20 evidence to make it look public. Create a
separate sanitized artifact with provenance if one is approved. Do not claim
that a V20 Scout result covers a new productization candidate image.

## Required gates before publication

Obtain owner decisions for LICENSE_DECISION_REQUIRED,
SECURITY_CONTACT_REQUIRED, and PUBLIC_OR_PRIVATE_INITIAL_GITHUB_REPOSITORY.
Then rerun secret and machine-path scans, inspect the exact source archive,
review dependency and license obligations, check artifact provenance, and
perform a fresh candidate-image scan under an approved policy.
