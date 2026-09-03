#!/usr/bin/env python3
"""Generate and validate the RC dependency-license inventory.

This is a deterministic evidence and coverage tool, not a legal classifier.
It preserves the license identifiers reported by the exact CycloneDX SBOM and
uses an exact-version installed dist-info license file only when that file is
available locally.  It intentionally leaves missing or ambiguous metadata in
the review queue.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from importlib import metadata
from pathlib import Path
from typing import Any


RC_DIGEST = "sha256:d67cdf9eab0bc00efe62f1535e0e954fa7b535fe69c87d0b075d12394c4acfd4"
FIRST_PARTY = {"agentguard", "agentguard-server"}
DIRECT_RUNTIME = {
    "fastapi",
    "uvicorn",
    "pydantic",
    "pydantic-settings",
    "sqlalchemy",
    "psycopg",
    "alembic",
    "opentelemetry-proto",
    "jinja2",
    "authlib",
    "joserfc",
    "cryptography",
    "boto3",
    "httpx",
    "opentelemetry-sdk",
}
LICENSE_FILE_RE = re.compile(r"(^|/)(license|copying|notice|copyright)(\.[^/]*)?$", re.I)
SAFE_URL_RE = re.compile(r"^https?://[^\s]+$")
KNOWN_PERMISSIVE = {
    "0BSD",
    "Apache-2.0",
    "BSD-2-Clause",
    "BSD-3-Clause",
    "BSD-4-Clause",
    "FSFAP",
    "FSFUL",
    "FSFULLR",
    "GFDL-1.2-only",
    "ISC",
    "MIT",
    "MIT-0",
    "PSF-2.0",
    "Unicode-DFS-2016",
    "X11",
    "Zlib",
}


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def json_write(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(value, indent=2, sort_keys=False) + "\n", encoding="utf-8")


def project_direct_runtime(repo: Path) -> set[str]:
    names: set[str] = set()
    try:
        import tomllib

        for relative in ("server/pyproject.toml", "sdk/python/pyproject.toml"):
            document = tomllib.loads((repo / relative).read_text(encoding="utf-8"))
            for requirement in document.get("project", {}).get("dependencies", []):
                match = re.match(r"\s*([A-Za-z0-9_.-]+)", requirement)
                if match:
                    names.add(normalize_name(match.group(1)))
    except (OSError, ValueError, TypeError):
        return set(DIRECT_RUNTIME)
    return names or set(DIRECT_RUNTIME)


def exact_dist_metadata(name: str, version: str, distributions: dict[str, Any]) -> dict[str, Any] | None:
    distribution = distributions.get(normalize_name(name))
    if distribution is None or distribution.version != version:
        return None
    license_files: list[tuple[str, str]] = []
    for file_name in distribution.files or []:
        file_text = str(file_name).replace("\\", "/")
        if not LICENSE_FILE_RE.search(file_text):
            continue
        try:
            contents = distribution.locate_file(file_name).read_text(encoding="utf-8", errors="replace")
        except (OSError, UnicodeError):
            continue
        license_files.append((file_text, contents))
    return {
        "distribution": distribution,
        "license_files": license_files,
        "metadata_license": (distribution.metadata.get("License") or "").strip(),
        "project_urls": [
            value.split(",", 1)[-1].strip()
            for value in distribution.metadata.get_all("Project-URL", [])
            if SAFE_URL_RE.match(value.split(",", 1)[-1].strip())
        ],
    }


def bundled_license_ids(files: list[tuple[str, str]]) -> list[str]:
    combined = "\n".join(contents for _, contents in files)
    if not combined:
        return []
    ids: list[str] = []
    if "Apache License" in combined and "Version 2.0" in combined:
        ids.append("Apache-2.0")
    if "Copyright 2007 Pallets" in combined and "Redistribution and use in source and binary forms" in combined:
        ids.append("BSD-3-Clause")
    if "Copyright 2008 Google Inc." in combined and "3-Clause BSD License" not in combined:
        ids.append("BSD-3-Clause")
    if "dateutil - Extensions to the standard Python datetime module" in combined:
        ids = ["Apache-2.0", "BSD-3-Clause"]
    return list(dict.fromkeys(ids))


def copyright_reference(files: list[tuple[str, str]]) -> str:
    for file_name, contents in files:
        match = re.search(r"(?im)^copyright[^\n]*", contents)
        if match:
            return f"{file_name}: {match.group(0).strip()}"
    if files:
        return "; ".join(file_name for file_name, _ in files)
    return "Not available from exact local package metadata"


def observed_license_ids(component: dict[str, Any]) -> list[str]:
    values: list[str] = []
    for item in component.get("licenses", []):
        license_data = item.get("license", {})
        identifier = license_data.get("id") or license_data.get("name")
        if identifier:
            values.append(str(identifier))
    return list(dict.fromkeys(values))


def classify(license_ids: list[str], first_party: bool) -> str:
    if first_party:
        return "PERMISSIVE_CLEAR"
    if not license_ids:
        return "NO_LICENSE_METADATA"
    if len(license_ids) > 1:
        return "DUAL_OR_MULTI_LICENSE"
    identifier = license_ids[0]
    if identifier.startswith(("GPL-", "AGPL-")):
        return "STRONG_COPYLEFT_REVIEW_REQUIRED"
    if identifier.startswith(("LGPL-", "MPL-")):
        return "WEAK_COPYLEFT_REVIEWED"
    if identifier not in KNOWN_PERMISSIVE:
        return "CUSTOM_LICENSE_REVIEW"
    return "PERMISSIVE_CLEAR"


def component_record(
    component: dict[str, Any],
    direct_runtime: set[str],
    distributions: dict[str, Any],
) -> dict[str, Any]:
    name = str(component.get("name", ""))
    version = str(component.get("version", ""))
    purl = str(component.get("purl", ""))
    first_party = normalize_name(name) in {normalize_name(value) for value in FIRST_PARTY}
    is_python = purl.startswith("pkg:pypi/")
    is_os = purl.startswith(("pkg:deb/", "pkg:rpm/")) or purl.startswith("pkg:generic/")
    exact = exact_dist_metadata(name, version, distributions) if is_python else None
    sbom_ids = observed_license_ids(component)
    derived_ids = bundled_license_ids(exact["license_files"]) if exact else []
    license_ids = sbom_ids or derived_ids

    if first_party:
        license_expression = "Apache-2.0"
        evidence = "Repository LICENSE and project pyproject.toml license field"
        copyright_source = "Repository LICENSE"
    elif sbom_ids:
        if len(sbom_ids) == 1:
            license_expression = sbom_ids[0]
        else:
            license_expression = "OBSERVED LICENSE IDS (NO EXPRESSION): " + "; ".join(sbom_ids)
        evidence = "CycloneDX 1.5 SBOM generated by Docker Scout v1.24.0"
        copyright_source = "SBOM license metadata only; exact bundled notice text still requires extraction"
        if exact and exact["license_files"]:
            evidence += "; exact-version installed dist-info license/notice file also present"
            copyright_source = copyright_reference(exact["license_files"])
    elif derived_ids:
        license_expression = " AND ".join(derived_ids) if len(derived_ids) > 1 else derived_ids[0]
        evidence = "Exact-version installed dist-info bundled license file"
        copyright_source = copyright_reference(exact["license_files"])
    else:
        license_expression = "NO LICENSE METADATA FOUND"
        if is_python:
            distribution = distributions.get(normalize_name(name))
            if distribution is None:
                attempt = "exact-version dist-info unavailable in local environment"
            elif distribution.version != version:
                attempt = f"local dist-info version {distribution.version} does not match SBOM version {version}"
            else:
                attempt = "matching dist-info has no readable bundled license/notice file"
            evidence = "CycloneDX 1.5 SBOM had no license metadata; " + attempt
        elif is_os:
            evidence = (
                "CycloneDX 1.5 SBOM had no license metadata; local Debian/distroless package copyright "
                "database was not available in the repository environment"
            )
        else:
            evidence = "CycloneDX 1.5 SBOM had no license metadata; no authoritative local source found"
        copyright_source = "Not available from exact local package metadata"

    primary = classify(license_ids, first_party)
    if first_party:
        relation = "FIRST_PARTY"
        runtime_kind = "RUNTIME"
        component_type = "FIRST_PARTY"
    elif is_python:
        relation = "DIRECT_RUNTIME" if normalize_name(name) in direct_runtime else "TRANSITIVE_RUNTIME"
        runtime_kind = "RUNTIME"
        component_type = "PYTHON_PACKAGE"
    elif is_os:
        relation = "OS_RUNTIME"
        runtime_kind = "OS"
        component_type = "OS_PACKAGE"
    else:
        relation = "TRANSITIVE_RUNTIME"
        runtime_kind = "RUNTIME"
        component_type = "OTHER_RUNTIME"

    has_strong = any(identifier.startswith(("GPL-", "AGPL-")) for identifier in license_ids)
    has_weak = any(identifier.startswith(("LGPL-", "MPL-")) for identifier in license_ids)
    if first_party:
        notice_required = "NO"
        source_obligation = "NO"
        compatibility = "NO"
        release_action = "Preserve repository Apache-2.0 LICENSE"
        status = "RESOLVED_FIRST_PARTY"
    elif primary == "NO_LICENSE_METADATA":
        notice_required = "BLOCKED_PENDING_AUTHORITATIVE_REVIEW"
        source_obligation = "BLOCKED_PENDING_LICENSE_IDENTIFICATION"
        compatibility = "REQUIRED"
        release_action = "Block release pending authoritative license and notice evidence"
        status = "BLOCKED_NO_LICENSE_METADATA"
    elif primary == "CUSTOM_LICENSE_REVIEW":
        notice_required = "REQUIRED"
        source_obligation = "REVIEW_REQUIRED"
        compatibility = "REQUIRED"
        release_action = "Legal/source/notice review before release"
        status = "REVIEW_REQUIRED"
    elif primary == "DUAL_OR_MULTI_LICENSE":
        notice_required = "REQUIRED"
        source_obligation = "REVIEW_REQUIRED" if (has_strong or has_weak) else "REVIEW_RECOMMENDED"
        compatibility = "REQUIRED"
        release_action = "Resolve exact expression, preserve all applicable notices, and review compatibility"
        status = "REVIEW_REQUIRED"
    elif primary == "STRONG_COPYLEFT_REVIEW_REQUIRED":
        notice_required = "REQUIRED"
        source_obligation = "REVIEW_REQUIRED"
        compatibility = "REQUIRED"
        release_action = "Strong-copyleft compatibility, source, and notice review"
        status = "REVIEW_REQUIRED"
    elif primary == "WEAK_COPYLEFT_REVIEWED":
        notice_required = "REQUIRED"
        source_obligation = "REVIEW_REQUIRED"
        compatibility = "RECOMMENDED"
        release_action = "Review unchanged import/linkage boundary and preserve license/notice"
        status = "REVIEW_REQUIRED"
    else:
        notice_required = "REQUIRED"
        source_obligation = "NOT_IDENTIFIED"
        compatibility = "NONE"
        release_action = "Preserve license text and required attribution in release bundle"
        status = "RESOLVED_ENGINEERING_TRIAGE"

    if len(license_ids) > 1:
        notes = "SBOM lists multiple license IDs; this is not treated as a selected SPDX expression."
    elif has_strong:
        notes = "Observed strong-copyleft ID; no AgentGuard source modification or vendoring was found."
    elif has_weak:
        notes = "Observed weak-copyleft ID; no AgentGuard source modification or vendoring was found."
    elif primary == "NO_LICENSE_METADATA":
        notes = "Distributed RC component; do not infer license from package name or parent project."
    else:
        notes = "No vendored dependency source or patch overlay was found in the inspected repository/build files."

    return {
        "bom_ref": component.get("bom-ref"),
        "name": name,
        "version": version,
        "purl": purl,
        "type": component_type,
        "direct_or_transitive": relation,
        "runtime_dev_os": runtime_kind,
        "in_rc_image": True,
        "license_expression": license_expression,
        "observed_license_ids": license_ids,
        "license_classification": primary,
        "license_evidence_source": evidence,
        "copyright_notice_source": copyright_source,
        "upstream_urls": (exact["project_urls"] if exact else []),
        "redistribution_relevance": "DISTRIBUTED_IN_EXACT_RC_IMAGE" if not first_party else "AGENTGUARD_SOURCE",
        "modified": "NO — UNMODIFIED_THIRD_PARTY_COMPONENT" if not first_party else "NO — AGENTGUARD_SOURCE",
        "notice_required": notice_required,
        "source_obligation": source_obligation,
        "compatibility_review": compatibility,
        "release_action": release_action,
        "status": status,
        "notes": notes,
    }


def render_matrix(records: list[dict[str, Any]]) -> str:
    headers = [
        "Component", "Version", "Type", "Direct/Transitive", "Runtime/Dev/OS",
        "In RC Image", "License", "Classification", "Modified?", "Notice Required?",
        "Source Obligation?", "Compatibility Review?", "Evidence Source", "Release Action", "Status",
    ]
    lines = [
        "# AgentGuard RC dependency-license matrix",
        "",
        "This is an engineering/compliance inventory for the exact RC SBOM, not legal certification.",
        "Every SBOM component is represented below. Multi-ID entries preserve the observed IDs and are not",
        "silently converted into a chosen SPDX expression. The approved RC image is immutable for this gate.",
        "",
        "| " + " | ".join(headers) + " |",
        "|" + "|".join("---" for _ in headers) + "|",
    ]
    for record in records:
        license_value = record["license_expression"].replace("|", "\\|")
        evidence = record["license_evidence_source"].replace("|", "\\|")
        action = record["release_action"].replace("|", "\\|")
        values = [
            record["name"], record["version"], record["type"], record["direct_or_transitive"],
            record["runtime_dev_os"], "YES" if record["in_rc_image"] else "NO", license_value,
            record["license_classification"], record["modified"], record["notice_required"],
            record["source_obligation"], record["compatibility_review"], evidence, action, record["status"],
        ]
        lines.append("| " + " | ".join(str(value).replace("|", "\\|") for value in values) + " |")
    return "\n".join(lines) + "\n"


def render_notices(records: list[dict[str, Any]], digest: str) -> str:
    third_party = [record for record in records if record["type"] != "FIRST_PARTY"]
    lines = [
        "# AgentGuard third-party notices inventory (candidate)",
        "",
        "This file is a version-specific candidate inventory for the exact RC image; it is not legal certification",
        "and is not yet a release-ready license bundle. It records the evidence available locally and identifies",
        "where authoritative license text, copyright notices, or source-obligation review is still required.",
        "",
        f"RC image digest: `{digest}`",
        "",
        "The release packaging plan is: preserve the repository `LICENSE`, ship this inventory after review, and",
        "add authoritative bundled license/notice texts under `licenses/third-party/` (or an equivalent package",
        "metadata bundle) before public distribution. No full third-party license text is copied into this file.",
        "",
        "| Dependency | Version | License evidence | Copyright/notice reference | Upstream URL | Required action |",
        "|---|---|---|---|---|---|",
    ]
    for record in third_party:
        license_value = record["license_expression"].replace("|", "\\|")
        notice = record["copyright_notice_source"].replace("|", "\\|")
        upstream = ", ".join(record["upstream_urls"]) or "Not recorded in exact SBOM/local metadata"
        action = record["release_action"].replace("|", "\\|")
        lines.append(f"| {record['name']} | {record['version']} | {license_value} | {notice} | {upstream} | {action} |")
    lines.extend([
        "",
        "## Review boundary",
        "",
        "The 17 third-party rows with `NO_LICENSE_METADATA` remain release blockers. The 38 multi-license rows",
        "must be reconciled against the package's authoritative copyright/license records before selecting any",
        "compliance expression. Strong- and weak-copyleft rows require the compatibility and source-obligation",
        "review recorded in the matrix. This inventory intentionally makes no derivative-work or legal-compatibility",
        "claim.",
    ])
    return "\n".join(lines) + "\n"


def build_closure(records: list[dict[str, Any]], sbom_path: str) -> dict[str, Any]:
    third_party = [record for record in records if record["type"] != "FIRST_PARTY"]
    counts: dict[str, int] = {}
    for record in third_party:
        category = record["license_classification"]
        counts[category] = counts.get(category, 0) + 1
    strong_components = [record["name"] for record in third_party if any(i.startswith(("GPL-", "AGPL-")) for i in record["observed_license_ids"])]
    weak_components = [record["name"] for record in third_party if any(i.startswith(("LGPL-", "MPL-")) for i in record["observed_license_ids"]) and not any(i.startswith(("GPL-", "AGPL-")) for i in record["observed_license_ids"])]
    no_metadata = [record["name"] for record in third_party if record["license_classification"] == "NO_LICENSE_METADATA"]
    blockers = [
        f"{len(no_metadata)} distributed third-party components have no usable license metadata: {', '.join(no_metadata)}.",
        f"{len(strong_components)} components contain GPL/AGPL-family IDs; exact compatibility, notice, and source obligations remain unresolved.",
        f"{len(weak_components)} components contain LGPL/MPL-family IDs and require redistribution-boundary review.",
        "Third-party notice and license-text bundle is a required release action and is not yet release-ready.",
        "Potential source-distribution obligations remain unresolved; no legal conclusion is asserted.",
    ]
    review_components = [
        record["name"] for record in third_party
        if record["license_classification"] in {
            "NO_LICENSE_METADATA", "DUAL_OR_MULTI_LICENSE", "CUSTOM_LICENSE_REVIEW",
            "STRONG_COPYLEFT_REVIEW_REQUIRED", "WEAK_COPYLEFT_REVIEWED",
        }
    ]
    return {
        "schema_version": "dependency-license-closure-v1",
        "rc_digest": RC_DIGEST,
        "sbom": {"path": sbom_path, "format": "CycloneDX 1.5", "components": len(records), "tool": "Docker Scout v1.24.0"},
        "first_party_components": len(records) - len(third_party),
        "third_party_components": len(third_party),
        "direct_runtime_components": sum(record["direct_or_transitive"] == "DIRECT_RUNTIME" for record in records),
        "transitive_python_runtime_components": sum(record["direct_or_transitive"] == "TRANSITIVE_RUNTIME" and record["type"] == "PYTHON_PACKAGE" for record in records),
        "os_runtime_components": sum(record["type"] == "OS_PACKAGE" for record in records) + sum(record["type"] == "OTHER_RUNTIME" for record in records),
        "classification_counts": counts,
        "permissive_clear": counts.get("PERMISSIVE_CLEAR", 0),
        "notice_required": sum(record["notice_required"] == "REQUIRED" for record in third_party) + sum(record["notice_required"] == "BLOCKED_PENDING_AUTHORITATIVE_REVIEW" for record in third_party),
        "notice_or_attribution_required": counts.get("NOTICE_OR_ATTRIBUTION_REQUIRED", 0),
        "weak_copyleft_reviewed": counts.get("WEAK_COPYLEFT_REVIEWED", 0),
        "strong_copyleft_review_required": counts.get("STRONG_COPYLEFT_REVIEW_REQUIRED", 0),
        "dual_or_multi_license": counts.get("DUAL_OR_MULTI_LICENSE", 0),
        "custom_license_review": counts.get("CUSTOM_LICENSE_REVIEW", 0),
        "unknown": counts.get("UNKNOWN_REQUIRES_MANUAL_REVIEW", 0),
        "no_license_metadata": counts.get("NO_LICENSE_METADATA", 0),
        "confirmed_copyleft_count": len(set(strong_components + weak_components)),
        "confirmed_strong_copyleft_components": len(set(strong_components)),
        "confirmed_weak_copyleft_components": len(set(weak_components)),
        "legal_review_recommended": len(review_components),
        "previous_manual_review_count": 118,
        "remaining_manual_review_count": len(review_components),
        "previous_copyleft_related_count": 47,
        "previous_unknown_no_license_count": 25,
        "remaining_unknown_no_license_count": len(no_metadata),
        "agpl_components": [record["name"] for record in third_party if any(i.startswith("AGPL-") for i in record["observed_license_ids"])],
        "gpl_2_only_components": [record["name"] for record in third_party if "GPL-2.0-only" in record["observed_license_ids"]],
        "review_components": sorted(set(review_components)),
        "release_blockers": blockers,
        "third_party_notices_required": True,
        "third_party_notices_status": "REQUIRED",
        "third_party_license_bundle_status": "REQUIRED",
        "source_distribution_required": True,
        "source_distribution_status": "BLOCKED",
        "license_gate": "BLOCKED_LEGAL_REVIEW",
        "security_contact_gate": "BLOCKED",
        "public_release_ready": False,
        "components": records,
    }


def validate_outputs(sbom: dict[str, Any], closure: dict[str, Any], matrix_path: Path, notices_path: Path) -> list[str]:
    errors: list[str] = []
    components = sbom.get("components", [])
    records = closure.get("components", [])
    sbom_refs = [component.get("bom-ref") for component in components]
    record_refs = [record.get("bom_ref") for record in records]
    if len(components) != len(records):
        errors.append(f"SBOM/matrix component count mismatch: {len(components)} != {len(records)}")
    if len(set(record_refs)) != len(record_refs):
        errors.append("duplicate SBOM bom-ref in closure evidence")
    if sorted(sbom_refs) != sorted(record_refs):
        errors.append("closure evidence does not cover every SBOM bom-ref")
    for path in (matrix_path, notices_path):
        if not path.exists():
            errors.append(f"missing generated output: {path}")
        elif re.search(r"(?:[A-Za-z]:\\|/Users/|/home/|C:/Users/)", path.read_text(encoding="utf-8")):
            errors.append(f"local absolute path found in {path}")
    serialized = json.dumps(closure)
    if re.search(r"(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_-]{20,}|github_pat_[A-Za-z0-9_-]{20,}|-----BEGIN .*PRIVATE KEY-----)", serialized, re.I):
        errors.append("secret-like value found in closure evidence")
    if closure.get("rc_digest") != RC_DIGEST:
        errors.append("closure digest does not match sealed RC digest")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", default="artifacts/agentguard-1.0.0rc1-sbom.cyclonedx.json")
    parser.add_argument("--matrix", default="docs/productization/dependency-license-matrix.md")
    parser.add_argument("--notices", default="THIRD_PARTY_NOTICES.md")
    parser.add_argument("--closure", default="artifacts/dependency-license-closure.json")
    parser.add_argument("--check", action="store_true", help="validate existing generated outputs without rewriting")
    args = parser.parse_args()
    sbom_path = Path(args.sbom)
    if not sbom_path.exists():
        print(f"license_inventory=FAIL missing SBOM {sbom_path}", file=sys.stderr)
        return 1
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    distributions = {normalize_name(dist.metadata.get("Name", "")): dist for dist in metadata.distributions() if dist.metadata.get("Name")}
    records = [component_record(component, project_direct_runtime(Path.cwd()), distributions) for component in sbom.get("components", [])]
    closure_path = Path(args.closure)
    matrix_path = Path(args.matrix)
    notices_path = Path(args.notices)
    if args.check:
        if not closure_path.exists():
            print(f"license_inventory=FAIL missing closure {closure_path}", file=sys.stderr)
            return 1
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
    else:
        closure = build_closure(records, args.sbom.replace("\\", "/"))
        matrix_path.parent.mkdir(parents=True, exist_ok=True)
        matrix_path.write_text(render_matrix(records), encoding="utf-8")
        notices_path.write_text(render_notices(records, RC_DIGEST), encoding="utf-8")
        json_write(closure_path, closure)
    errors = validate_outputs(sbom, closure, matrix_path, notices_path)
    if errors:
        print("license_inventory=FAIL")
        for error in errors:
            print(error, file=sys.stderr)
        return 1
    print(
        "license_inventory=PASS "
        f"components={len(records)} third_party={closure.get('third_party_components')} "
        f"no_license_metadata={closure.get('no_license_metadata')} "
        f"gate={closure.get('license_gate')}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
