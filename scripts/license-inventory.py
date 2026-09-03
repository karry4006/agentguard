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
CURATED_EVIDENCE_PATH = "licenses/license-evidence.json"
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

# These are the distributed records whose exact source evidence identifies a
# GPL-family license as the primary runtime license. Other GPL-family IDs in
# the SBOM are retained as observed facts, but are file-scoped, source-package,
# documentation, packaging, or detector-aggregation records.
ACTUAL_GPL_PRIMARY = {
    "base-files",
    "netbase",
    "readline",
    "libreadline8t64",
    "libgcc-s1",
    "libgomp1",
    "libstdc++6",
    "gcc-14-base",
}


def normalize_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def load_curated_evidence(path: Path) -> dict[str, dict[str, Any]]:
    """Load reviewed overrides without making network access mandatory."""
    if not path.exists():
        return {}
    document = json.loads(path.read_text(encoding="utf-8"))
    by_key: dict[str, dict[str, Any]] = {}

    def add(key: str, value: dict[str, Any]) -> None:
        if key:
            by_key[key] = value

    for entry in document.get("entries", []):
        entry = dict(entry)
        if "classification" in entry and "license_classification" not in entry:
            entry["license_classification"] = entry["classification"]
        if "evidence_source" in entry and "license_evidence_source" not in entry:
            entry["license_evidence_source"] = entry["evidence_source"]
        add(str(entry.get("purl", "")), entry)
        add(f"{normalize_name(str(entry.get('component', '')))}@{entry.get('version', '')}", entry)
    for group in document.get("source_groups", []) + document.get("source_groups_additional", []):
        for component in group.get("components", []):
            value = dict(group)
            value["component"] = component
            if "classification" in value and "license_classification" not in value:
                value["license_classification"] = value["classification"]
            if "evidence_source" in value and "license_evidence_source" not in value:
                value["license_evidence_source"] = value["evidence_source"]
            value.setdefault("review_status", "FACTUALLY_RESOLVED_FILE_SCOPED_TERMS")
            value.setdefault("evidence_type", "EXACT_IMAGE_DEBIAN_COPYRIGHT" if group.get("source_package") else "EXACT_VERSION_PACKAGE_METADATA")
            value.setdefault("evidence_version", group.get("source_version", ""))
            value.setdefault("evidence_source", f"exact RC image {group.get('copyright_path')}" if group.get("copyright_path") else "Exact RC image package copyright/source metadata")
            value.setdefault("copyright_notice_source", group.get("copyright_path", "Exact RC image package copyright/source metadata"))
            value.setdefault("source_obligation", "REVIEW_REQUIRED")
            value.setdefault("notice_required", "LICENSE_REQUIRED_NOTICE")
            value.setdefault("compatibility_review", "REQUIRED" if group.get("gpl_family_role", "").startswith("PRIMARY") else "REVIEW_RECOMMENDED")
            value.setdefault("runtime_boundary", "OS_BASE_COMPONENT")
            value.setdefault("current_ambiguity_reason", "Exact source/package evidence is recorded; any remaining issue is legal interpretation, not missing metadata.")
            value.setdefault("next_evidence_source", "Final authoritative license-text and source-bundle review")
            value.setdefault("source_archive_or_tag", f"Debian source package {group.get('source_package', '')} {group.get('source_version', '')}".strip())
            value.setdefault("source_path", "Exact RC image /usr/share/doc/*/copyright")
            add(f"{normalize_name(component)}@{group.get('component_versions', {}).get(component, '')}", value)
            add(f"{normalize_name(component)}@*", value)
    for entry in document.get("nested_wheel_components", []):
        entry = dict(entry)
        if "classification" in entry and "license_classification" not in entry:
            entry["license_classification"] = entry["classification"]
        if "evidence_source" in entry and "license_evidence_source" not in entry:
            entry["license_evidence_source"] = entry["evidence_source"]
        add(str(entry.get("purl", "")), entry)
        add(f"{normalize_name(str(entry.get('component', '')))}@{entry.get('version', '')}", entry)
    return by_key


def curated_for(component: dict[str, Any], curated: dict[str, dict[str, Any]]) -> dict[str, Any]:
    name = normalize_name(str(component.get("name", "")))
    version = str(component.get("version", ""))
    return curated.get(str(component.get("purl", ""))) or curated.get(f"{name}@{version}") or curated.get(f"{name}@*") or {}


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
    curated: dict[str, dict[str, Any]],
) -> dict[str, Any]:
    name = str(component.get("name", ""))
    version = str(component.get("version", ""))
    purl = str(component.get("purl", ""))
    curated_entry = curated_for(component, curated)
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
    if first_party:
        runtime_boundary = "PYTHON_IMPORTED_LIBRARY"
    elif is_os:
        runtime_boundary = "OS_BASE_COMPONENT"
    elif is_python and relation == "DIRECT_RUNTIME":
        runtime_boundary = "PYTHON_IMPORTED_LIBRARY"
    elif is_python:
        runtime_boundary = "TRANSITIVE_LIBRARY"
    else:
        runtime_boundary = "TRANSITIVE_LIBRARY"

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
        notice_required = "LICENSE_REQUIRED_NOTICE"
        source_obligation = "REVIEW_REQUIRED"
        compatibility = "REQUIRED"
        release_action = "Legal/source/notice review before release"
        status = "REVIEW_REQUIRED"
    elif primary == "DUAL_OR_MULTI_LICENSE":
        notice_required = "LICENSE_REQUIRED_NOTICE"
        source_obligation = "REVIEW_REQUIRED" if (has_strong or has_weak) else "REVIEW_RECOMMENDED"
        compatibility = "REQUIRED"
        release_action = "Resolve exact expression, preserve all applicable notices, and review compatibility"
        status = "REVIEW_REQUIRED"
    elif primary == "STRONG_COPYLEFT_REVIEW_REQUIRED":
        notice_required = "LICENSE_REQUIRED_NOTICE"
        source_obligation = "REVIEW_REQUIRED"
        compatibility = "REQUIRED"
        release_action = "Strong-copyleft compatibility, source, and notice review"
        status = "REVIEW_REQUIRED"
    elif primary == "WEAK_COPYLEFT_REVIEWED":
        notice_required = "LICENSE_REQUIRED_NOTICE"
        source_obligation = "REVIEW_REQUIRED"
        compatibility = "RECOMMENDED"
        release_action = "Review unchanged import/linkage boundary and preserve license/notice"
        status = "REVIEW_REQUIRED"
    else:
        notice_required = "LICENSE_REQUIRED_NOTICE"
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

    record = {
        "bom_ref": component.get("bom-ref"),
        "name": name,
        "version": version,
        "purl": purl,
        "type": component_type,
        "direct_or_transitive": relation,
        "runtime_dev_os": runtime_kind,
        "runtime_boundary": runtime_boundary,
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
    if curated_entry:
        for key in (
            "license_expression", "license_classification", "license_evidence_source",
            "copyright_notice_source", "source_obligation", "compatibility_review",
            "notice_required", "status", "release_action", "runtime_boundary", "source_package",
            "source_version", "source_archive_or_tag", "source_path", "review_status",
            "current_ambiguity_reason", "next_evidence_source", "selected_license_if_multi",
            "license_options", "gpl_family_role", "evidence_type", "evidence_version",
            "source_archive_sha256", "parent", "parent_file", "auditwheel_sbom_sha256",
        ):
            if key in curated_entry:
                record[key] = curated_entry[key]
        if curated_entry.get("observed_license_ids") is not None:
            record["observed_license_ids"] = curated_entry["observed_license_ids"]
        if curated_entry.get("type"):
            record["type"] = curated_entry["type"]
        if curated_entry.get("direct_or_transitive"):
            record["direct_or_transitive"] = curated_entry["direct_or_transitive"]
        if curated_entry.get("runtime_dev_os"):
            record["runtime_dev_os"] = curated_entry["runtime_dev_os"]
        if curated_entry.get("redistribution_relevance"):
            record["redistribution_relevance"] = curated_entry["redistribution_relevance"]
        if curated_entry.get("modified"):
            record["modified"] = curated_entry["modified"]
        if curated_entry.get("upstream_urls") is not None:
            record["upstream_urls"] = curated_entry["upstream_urls"]
        elif SAFE_URL_RE.match(str(curated_entry.get("evidence_source", ""))):
            record["upstream_urls"] = [str(curated_entry["evidence_source"])]
        if curated_entry.get("copyright_path") and "copyright_notice_source" not in curated_entry:
            record["copyright_notice_source"] = str(curated_entry["copyright_path"])
        elif curated_entry.get("source_path") and record["copyright_notice_source"].startswith("SBOM license metadata"):
            record["copyright_notice_source"] = str(curated_entry["source_path"])
        if curated_entry.get("current_ambiguity_reason"):
            record["notes"] = curated_entry["current_ambiguity_reason"]
        if curated_entry.get("review_status", "").startswith("FACTUALLY_RESOLVED"):
            if record["license_classification"] == "PERMISSIVE_CLEAR":
                record["status"] = "RESOLVED_ENGINEERING_TRIAGE"
                record["release_action"] = "Preserve exact license, copyright, and applicable attribution in release bundle"
            elif record["license_classification"] == "DUAL_OR_MULTI_LICENSE":
                record["status"] = curated_entry.get("status", "FACTUALLY_RESOLVED")
                if record.get("selected_license_if_multi"):
                    record["release_action"] = "Preserve the selected license option and all file-scoped notices; retain owner/legal review where recorded"
                else:
                    record["release_action"] = "Preserve exact file-scoped license and notice records; retain owner/legal review where recorded"
        if curated_entry.get("license_status") == "UNRESOLVED_LICENSE_EVIDENCE":
            # These six records are embedded in the exact psycopg-binary
            # auditwheel SBOM. They are not Debian base-image packages and
            # have no usable license metadata in that embedded record.
            record.update({
                "type": "NATIVE_WHEEL_COMPONENT",
                "direct_or_transitive": "TRANSITIVE_RUNTIME",
                "runtime_dev_os": "RUNTIME",
                "license_expression": "NO LICENSE METADATA FOUND",
                "license_classification": "NO_LICENSE_METADATA",
                "observed_license_ids": [],
                "license_evidence_source": (
                    "Exact RC image embedded auditwheel SBOM for psycopg-binary "
                    f"(sha256:{curated_entry.get('auditwheel_sbom_sha256', 'not-recorded')})"
                ),
                "copyright_notice_source": "No license metadata in embedded auditwheel SBOM",
                "notice_required": "BLOCKED_PENDING_AUTHORITATIVE_REVIEW",
                "source_obligation": "BLOCKED_PENDING_LICENSE_IDENTIFICATION",
                "compatibility_review": "REQUIRED",
                "release_action": "Block release pending exact CentOS source RPM/spec and bundled notice evidence",
                "status": "BLOCKED_NO_LICENSE_METADATA",
                "runtime_boundary": "BUNDLED_NATIVE_WHEEL_SHARED_LIBRARY",
                "review_status": "UNRESOLVED_FACTUAL_EVIDENCE",
                "next_evidence_source": curated_entry.get("next_evidence_source", "Official exact-version CentOS source RPM/spec"),
                "evidence_type": "EXACT_IMAGE_EMBEDDED_AUDITWHEEL_SBOM",
                "evidence_version": curated_entry.get("version", ""),
            })
    if record.get("name") in ACTUAL_GPL_PRIMARY:
        record["gpl_family_role"] = record.get("gpl_family_role") or "PRIMARY"
    elif any(identifier.startswith(("GPL-", "AGPL-")) for identifier in record["observed_license_ids"]):
        record["gpl_family_role"] = record.get("gpl_family_role") or "SECONDARY_OR_FILE_SCOPED"
    return record


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
        if record.get("selected_license_if_multi"):
            license_value += " [SELECTED=" + str(record["selected_license_if_multi"]) + "]"
        evidence = record["license_evidence_source"].replace("|", "\\|")
        if record.get("runtime_boundary"):
            evidence += " [BOUNDARY=" + str(record["runtime_boundary"]) + "]"
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
        "Every distributed third-party row is also covered by `PROJECT_POLICY_NOTICE` for traceability. The",
        "`LICENSE_REQUIRED_NOTICE` value is reserved for license-specific text, attribution, or NOTICE action",
        "identified by exact package evidence; policy inventory coverage is not treated as a legal conclusion.",
        "",
    ]
    groups = [
        ("Permissive dependencies", lambda r: r["license_classification"] == "PERMISSIVE_CLEAR"),
        ("Notice-bearing dependencies", lambda r: r["notice_required"] != "NO" and r["license_classification"] in {"CUSTOM_LICENSE_REVIEW", "DUAL_OR_MULTI_LICENSE"}),
        ("Weak-copyleft dependencies", lambda r: r["license_classification"] == "WEAK_COPYLEFT_REVIEWED"),
        ("Strong-copyleft/runtime dependencies", lambda r: r["license_classification"] == "STRONG_COPYLEFT_REVIEW_REQUIRED"),
        ("OS/base-image and nested native components", lambda r: r["type"] in {"OS_PACKAGE", "NATIVE_WHEEL_COMPONENT"} and r["license_classification"] not in {"PERMISSIVE_CLEAR", "DUAL_OR_MULTI_LICENSE"}),
        ("Unresolved license evidence", lambda r: r["license_classification"] == "NO_LICENSE_METADATA"),
    ]
    emitted: set[str] = set()
    for label, predicate in groups:
        selected = [record for record in third_party if predicate(record)]
        if not selected:
            continue
        lines.extend(["", f"## {label}", "", "| Dependency | Version | License evidence | Copyright/notice reference | Upstream URL | Required action |", "|---|---|---|---|---|---|"])
        for record in selected:
            emitted.add(record["name"] + "@" + record["version"])
            license_value = record["license_expression"].replace("|", "\\|")
            if record.get("selected_license_if_multi"):
                license_value += " [SELECTED=" + str(record["selected_license_if_multi"]) + "]"
            notice = record["copyright_notice_source"].replace("|", "\\|")
            upstream = ", ".join(record["upstream_urls"]) or "Not recorded in exact SBOM/local metadata"
            action = record["release_action"].replace("|", "\\|")
            lines.append(f"| {record['name']} | {record['version']} | {license_value} | {notice} | {upstream} | {action} |")
    remaining = [record for record in third_party if record["name"] + "@" + record["version"] not in emitted]
    if remaining:
        lines.extend(["", "## Other distributed components", "", "| Dependency | Version | License evidence | Copyright/notice reference | Upstream URL | Required action |", "|---|---|---|---|---|---|"])
        for record in remaining:
            lines.append(f"| {record['name']} | {record['version']} | {record['license_expression']} | {record['copyright_notice_source']} | {', '.join(record['upstream_urls']) or 'Not recorded in exact SBOM/local metadata'} | {record['release_action']} |")
    lines.extend([
        "",
        "## Review boundary",
        "",
        "The six nested native rows with `NO_LICENSE_METADATA` remain release blockers. The multi-license rows",
        "retain exact package/source evidence and selected options only where upstream explicitly grants a choice.",
        "Strong- and weak-copyleft rows require the compatibility and source-obligation",
        "review recorded in the matrix. This inventory intentionally makes no derivative-work or legal-compatibility",
        "claim.",
    ])
    return "\n".join(lines) + "\n"


def build_source_bundle_plan(records: list[dict[str, Any]]) -> dict[str, Any]:
    """Create a deterministic plan; this does not download or publish sources."""
    planned: list[dict[str, Any]] = []
    for record in sorted(records, key=lambda value: (value["name"].lower(), value["version"])):
        if record["type"] == "FIRST_PARTY":
            continue
        if record["source_obligation"] not in {"REVIEW_REQUIRED", "BLOCKED_PENDING_LICENSE_IDENTIFICATION"}:
            continue
        safe_name = re.sub(r"[^A-Za-z0-9_.-]+", "-", record["name"]).strip("-")
        planned.append({
            "component": record["name"],
            "version": record["version"],
            "purl": record["purl"],
            "source_package": record.get("source_package", record["name"]),
            "source_version": record.get("source_version", record["version"]),
            "download_or_source_origin": record.get("source_archive_or_tag") or record.get("next_evidence_source", "Official exact-version source required"),
            "upstream_urls": record.get("upstream_urls", []),
            "hash_if_acquired": record.get("source_archive_sha256") or record.get("auditwheel_sbom_sha256") or None,
            "license": record["license_expression"],
            "required_files": [record.get("source_path") or "Exact LICENSE/COPYING/NOTICE/copyright files"],
            "patches": "NONE_FOUND",
            "build_install_information": record.get("parent_file", "NO_AGENTGUARD_MODIFICATION_OR_PATCH_OVERLAY_FOUND"),
            "planned_release_location": f"licenses/third-party/{safe_name}-{record['version']}-LICENSE.txt",
            "status": "BLOCKED" if record["license_classification"] == "NO_LICENSE_METADATA" else "REVIEW_REQUIRED",
        })
    return {
        "schema_version": "license-source-bundle-plan-v1",
        "purpose": "Engineering plan only; no source archive is published by this artifact.",
        "rc_digest": RC_DIGEST,
        "source_plan_status": "BLOCKED_PENDING_OWNER_LEGAL_REVIEW",
        "official_sources_only": True,
        "downloaded_source_archives": [],
        "components": planned,
    }


def render_source_provenance(records: list[dict[str, Any]]) -> str:
    relevant = [record for record in records if record["type"] != "FIRST_PARTY" and (
        record.get("source_obligation") in {"REVIEW_REQUIRED", "BLOCKED_PENDING_LICENSE_IDENTIFICATION"}
        or record.get("gpl_family_role", "").startswith("PRIMARY")
    )]
    lines = [
        "# AgentGuard RC source provenance",
        "",
        "This is an engineering provenance record for the sealed RC image, not a legal certification or a source release.",
        f"The image is identified by `{RC_DIGEST}`. No source archive was downloaded or published by this gate.",
        "Only exact-version package metadata, official upstream locations, and official Debian/CentOS source locations are acceptable for final bundle assembly.",
        "",
        "## Component provenance",
        "",
        "| Component | Binary version | Source package/project | Source version | License evidence | Source origin | Modifications/patches | Distribution status |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for record in sorted(relevant, key=lambda value: (value["name"].lower(), value["version"])):
        origin = record.get("source_archive_or_tag") or record.get("next_evidence_source", "Official exact-version source required")
        urls = ", ".join(record.get("upstream_urls", []))
        if urls:
            origin += "; " + urls
        source = record.get("source_package", record["name"])
        lines.append("| " + " | ".join([
            record["name"], record["version"], source, record.get("source_version", record["version"]),
            record["license_expression"], origin.replace("|", "\\|"),
            record.get("local_modifications", record.get("modified", "NONE_FOUND")),
            record.get("source_obligation", "NOT_IDENTIFIED"),
        ]) + " |")
    lines.extend([
        "",
        "## Native wheel boundary",
        "",
        "The six unresolved `NATIVE_WHEEL_COMPONENT` records are shared libraries embedded by the exact `psycopg-binary` auditwheel payload.",
        "They are not Debian base-image package records. Their exact CentOS source RPM/spec provenance and license texts remain to be acquired from official CentOS sources.",
        "The embedded auditwheel SBOM hash is recorded in `licenses/license-evidence.json` and the source-bundle plan.",
        "",
        "## Release boundary",
        "",
        "No AgentGuard source was modified, vendored, or overlaid for these dependencies. This document records engineering facts and planned evidence locations; it does not decide derivative-work, compatibility, or source-offer questions.",
    ])
    return "\n".join(lines) + "\n"


def build_closure(records: list[dict[str, Any]], sbom: dict[str, Any], sbom_path: str, curated_document: dict[str, Any]) -> dict[str, Any]:
    third_party = [record for record in records if record["type"] != "FIRST_PARTY"]
    counts: dict[str, int] = {}
    for record in third_party:
        category = record["license_classification"]
        counts[category] = counts.get(category, 0) + 1
    original_components = sbom.get("components", [])
    original_by_key = {(str(c.get("name")), str(c.get("version"))): c for c in original_components}
    previous_no_metadata = {
        "libcom_err", "botocore", "python3.13-venv", "libxcrypt", "python", "libzstd",
        "media-types", "tzdata-legacy", "libcrypt1", "tzdata", "gcc-14", "krb5-libs",
        "libselinux", "keyutils-libs", "pcre", "cyrus-sasl-lib", "uvloop",
    }
    strong_components = [record["name"] for record in third_party if any(i.startswith(("GPL-", "AGPL-")) for i in record["observed_license_ids"])]
    weak_components = [record["name"] for record in third_party if any(i.startswith(("LGPL-", "MPL-")) for i in record["observed_license_ids"]) and not any(i.startswith(("GPL-", "AGPL-")) for i in record["observed_license_ids"])]
    no_metadata = [record["name"] for record in third_party if record["license_classification"] == "NO_LICENSE_METADATA"]
    remaining_missing_names = {record["name"] for record in third_party if record["license_classification"] == "NO_LICENSE_METADATA"}
    resolved_missing = sorted(previous_no_metadata - remaining_missing_names)
    actual_primary_names = sorted({record["name"] for record in third_party if record.get("gpl_family_role", "").startswith("PRIMARY")})
    alternative_only_names = sorted({record["name"] for record in third_party if record.get("gpl_family_role") == "ALTERNATIVE_ONLY"})
    gpl_python = sorted({record["name"] for record in third_party if record["type"] == "PYTHON_PACKAGE" and any(i.startswith(("GPL-", "AGPL-")) for i in record["observed_license_ids"])})
    review_components = [
        record["name"] for record in third_party
        if record["license_classification"] in {
            "NO_LICENSE_METADATA", "CUSTOM_LICENSE_REVIEW", "WEAK_COPYLEFT_REVIEWED",
        }
        or record.get("gpl_family_role", "").startswith("PRIMARY")
        or (
            record["license_classification"] == "STRONG_COPYLEFT_REVIEW_REQUIRED"
            and not record.get("review_status", "").startswith("FACTUALLY_RESOLVED")
        )
    ]
    source_components = sorted({record["name"] for record in third_party if record["source_obligation"] in {"REVIEW_REQUIRED", "BLOCKED_PENDING_LICENSE_IDENTIFICATION"}})
    multi_records = {
        str(component.get("name")) for component in original_components if len(component.get("licenses", [])) > 1
    }
    multi_records.update(record["name"] for record in third_party if len(record["observed_license_ids"]) > 1 and record["name"] == "python-dateutil")
    multi_total = len(multi_records)
    multi_curated = sum(
        record["name"] in multi_records
        and record["license_classification"] == "DUAL_OR_MULTI_LICENSE"
        and bool(record.get("current_ambiguity_reason"))
        for record in third_party
    )
    blockers = [
        f"{len(no_metadata)} nested native components remain without authoritative license evidence: {', '.join(no_metadata)}.",
        f"{len(actual_primary_names)} GPL-family components have an actual primary/runtime license role requiring compatibility and source-obligation review: {', '.join(actual_primary_names)}.",
        "The exact SBOM contains six nested CentOS/RPM records from psycopg-binary auditwheel metadata; their package licenses are not present in that embedded SBOM.",
        "Third-party notice and license-text bundle is a required release action and is not yet release-ready.",
        "The two first-party SBOM package records report 0.1.0a1 while the RC source/container is 1.0.0rc1; future packaging must align this identity without changing this sealed image.",
    ]
    remaining_questions = [
        "Confirm the six bundled native library licenses from the exact CentOS 7 source RPM/spec records and preserve their notices.",
        "Confirm the intended compliance path for GPL-3.0-or-later with GCC Runtime Library Exception 3.1 and the GPL-3.0 readline runtime.",
        "Confirm the BSD option for libzstd and preserve its zlib/Expat file-scoped notices.",
        "Confirm final corresponding-source/source-offer handling for the actual distributed native libraries.",
        "Confirm final third-party license-text and notice bundle contents.",
    ]
    unresolved_queue = [
        {
            "name": record["name"],
            "version": record["version"],
            "purl": record["purl"],
            "type": record["type"],
            "runtime_classification": record["runtime_dev_os"],
            "in_rc_image": record["in_rc_image"],
            "current_license_evidence": record["license_evidence_source"],
            "current_ambiguity_reason": record.get("current_ambiguity_reason", record["notes"]),
            "next_evidence_source": record.get("next_evidence_source", "Official exact-version source/package evidence"),
        }
        for record in sorted(third_party, key=lambda value: (value["name"].lower(), value["version"]))
        if record["license_classification"] == "NO_LICENSE_METADATA"
    ]
    return {
        "schema_version": "dependency-license-closure-v2",
        "evidence_resolution_version": "2026-09-03.exact-image-v2",
        "rc_digest": RC_DIGEST,
        "sbom": {"path": sbom_path, "format": "CycloneDX 1.5", "components": len(records), "tool": "Docker Scout v1.24.0"},
        "first_party_components": len(records) - len(third_party),
        "third_party_components": len(third_party),
        "direct_runtime_components": sum(record["direct_or_transitive"] == "DIRECT_RUNTIME" for record in records),
        "transitive_python_runtime_components": sum(record["direct_or_transitive"] == "TRANSITIVE_RUNTIME" and record["type"] == "PYTHON_PACKAGE" for record in records),
        "nested_wheel_native_components": sum(record["type"] == "NATIVE_WHEEL_COMPONENT" for record in records),
        "os_runtime_components": sum(record["type"] == "OS_PACKAGE" for record in records) + sum(record["type"] == "OTHER_RUNTIME" for record in records),
        "development_only_components": ["bandit", "coverage", "pip-audit", "pytest", "pytest-cov"],
        "classification_counts": counts,
        "permissive_clear": counts.get("PERMISSIVE_CLEAR", 0),
        "notice_required": sum(record["notice_required"] != "NO" for record in third_party),
        "project_policy_notice_count": len(third_party),
        "license_required_notice_count": len(third_party) - len(no_metadata),
        "notice_or_attribution_required": counts.get("NOTICE_OR_ATTRIBUTION_REQUIRED", 0),
        "weak_copyleft_reviewed": counts.get("WEAK_COPYLEFT_REVIEWED", 0),
        "strong_copyleft_review_required": counts.get("STRONG_COPYLEFT_REVIEW_REQUIRED", 0),
        "dual_or_multi_license": counts.get("DUAL_OR_MULTI_LICENSE", 0),
        "custom_license_review": counts.get("CUSTOM_LICENSE_REVIEW", 0),
        "unknown": counts.get("UNKNOWN_REQUIRES_MANUAL_REVIEW", 0),
        "no_license_metadata": counts.get("NO_LICENSE_METADATA", 0),
        "resolved_missing_license_count": len(resolved_missing),
        "remaining_missing_license_count": len(no_metadata),
        "resolved_missing_license_components": sorted(set(resolved_missing)),
        "remaining_missing_license_components": sorted(set(no_metadata)),
        "unresolved_component_queue": unresolved_queue,
        "multi_license_total": multi_total,
        "multi_license_normalized": multi_curated,
        "multi_license_remaining_ambiguous": max(0, multi_total - multi_curated),
        "confirmed_copyleft_count": len(set(strong_components + weak_components)),
        "confirmed_strong_copyleft_components": len(set(strong_components)),
        "confirmed_weak_copyleft_components": len(set(weak_components)),
        "gpl_family_observed": len(set(strong_components)),
        "gpl_family_primary": len(actual_primary_names),
        "gpl_family_alternative_only": len(alternative_only_names),
        "gpl_family_secondary_or_file_scoped": max(0, len(set(strong_components)) - len(actual_primary_names) - len(alternative_only_names)),
        "gpl_family_os_runtime": len(set(strong_components) - set(gpl_python)),
        "gpl_family_python_runtime": len(set(gpl_python)),
        "gpl_family_dev_only": 0,
        "strong_copyleft_actual_review_count": len(actual_primary_names),
        "gpl_family_requires_legal_review": len(actual_primary_names),
        "legal_review_recommended": len(set(review_components)),
        "source_obligation_components": source_components,
        "previous_manual_review_count": 71,
        "remaining_manual_review_count": len(set(review_components)),
        "previous_copyleft_related_count": 47,
        "previous_unknown_no_license_count": 17,
        "remaining_unknown_no_license_count": len(no_metadata),
        "agpl_components": [record["name"] for record in third_party if any(i.startswith("AGPL-") for i in record["observed_license_ids"])],
        "gpl_2_only_components": [record["name"] for record in third_party if "GPL-2.0-only" in record["observed_license_ids"]],
        "gpl_2_only_actual_primary": [name for name in actual_primary_names if name in {"base-files", "netbase"}],
        "review_components": sorted(set(review_components)),
        "remaining_legal_questions": remaining_questions,
        "release_blockers": blockers,
        "third_party_notices_required": True,
        "third_party_notices_complete": False,
        "third_party_notices_status": "REQUIRED",
        "third_party_license_bundle_status": "REQUIRED",
        "license_text_bundle_complete": False,
        "source_distribution_required": True,
        "source_distribution_status": "BLOCKED",
        "license_gate": "BLOCKED_LEGAL_REVIEW",
        "security_contact_gate": "BLOCKED",
        "public_release_ready": False,
        "curated_evidence_file": "licenses/license-evidence.json",
        "components": records,
    }


def validate_outputs(
    sbom: dict[str, Any],
    closure: dict[str, Any],
    matrix_path: Path,
    notices_path: Path,
    provenance_path: Path,
    source_plan_path: Path,
    evidence_path: Path,
) -> list[str]:
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
    for path in (matrix_path, notices_path, provenance_path, source_plan_path, evidence_path):
        if not path.exists():
            errors.append(f"missing generated output: {path}")
        elif re.search(r"(?:[A-Za-z]:\\|/Users/|/home/|C:/Users/)", path.read_text(encoding="utf-8")):
            errors.append(f"local absolute path found in {path}")
    serialized = json.dumps(closure)
    if re.search(r"(?:sk-[A-Za-z0-9_-]{20,}|ghp_[A-Za-z0-9_-]{20,}|github_pat_[A-Za-z0-9_-]{20,}|-----BEGIN .*PRIVATE KEY-----)", serialized, re.I):
        errors.append("secret-like value found in closure evidence")
    if closure.get("rc_digest") != RC_DIGEST:
        errors.append("closure digest does not match sealed RC digest")
    if closure.get("remaining_missing_license_count") != len(closure.get("remaining_missing_license_components", [])):
        errors.append("remaining missing-license count does not match explicit queue")
    if closure.get("multi_license_remaining_ambiguous", 1) != 0:
        errors.append("multi-license records remain without a normalized evidence/ambiguity entry")
    if any(not record.get("license_evidence_source") for record in closure.get("components", [])):
        errors.append("matrix record lacks license evidence source")
    if any(not record.get("runtime_boundary") for record in closure.get("components", [])):
        errors.append("matrix record lacks runtime boundary")
    source_names = {item.get("component") for item in json.loads(source_plan_path.read_text(encoding="utf-8")).get("components", [])} if source_plan_path.exists() else set()
    for record in closure.get("components", []):
        if record.get("source_obligation") in {"REVIEW_REQUIRED", "BLOCKED_PENDING_LICENSE_IDENTIFICATION"} and record.get("name") not in source_names:
            errors.append(f"source-obligation component missing from source plan: {record.get('name')}")
    for path in (matrix_path, notices_path, provenance_path, source_plan_path, evidence_path):
        if path.exists() and re.search(r"(?:[A-Za-z]:\\|/Users/|/home/|C:/Users/)", path.read_text(encoding="utf-8")):
            errors.append(f"local absolute path found in {path}")
    return errors


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--sbom", default="artifacts/agentguard-1.0.0rc1-sbom.cyclonedx.json")
    parser.add_argument("--matrix", default="docs/productization/dependency-license-matrix.md")
    parser.add_argument("--notices", default="THIRD_PARTY_NOTICES.md")
    parser.add_argument("--closure", default="artifacts/dependency-license-closure.json")
    parser.add_argument("--evidence", default=CURATED_EVIDENCE_PATH)
    parser.add_argument("--provenance", default="docs/productization/source-provenance.md")
    parser.add_argument("--source-plan", default="artifacts/license-source-bundle-plan.json")
    parser.add_argument("--check", action="store_true", help="validate existing generated outputs without rewriting")
    args = parser.parse_args()
    sbom_path = Path(args.sbom)
    if not sbom_path.exists():
        print(f"license_inventory=FAIL missing SBOM {sbom_path}", file=sys.stderr)
        return 1
    sbom = json.loads(sbom_path.read_text(encoding="utf-8"))
    distributions = {normalize_name(dist.metadata.get("Name", "")): dist for dist in metadata.distributions() if dist.metadata.get("Name")}
    evidence_path = Path(args.evidence)
    curated_document = json.loads(evidence_path.read_text(encoding="utf-8")) if evidence_path.exists() else {}
    curated = load_curated_evidence(evidence_path)
    records = [component_record(component, project_direct_runtime(Path.cwd()), distributions, curated) for component in sbom.get("components", [])]
    closure_path = Path(args.closure)
    matrix_path = Path(args.matrix)
    notices_path = Path(args.notices)
    provenance_path = Path(args.provenance)
    source_plan_path = Path(args.source_plan)
    if args.check:
        if not closure_path.exists():
            print(f"license_inventory=FAIL missing closure {closure_path}", file=sys.stderr)
            return 1
        closure = json.loads(closure_path.read_text(encoding="utf-8"))
    else:
        closure = build_closure(records, sbom, args.sbom.replace("\\", "/"), curated_document)
        matrix_path.parent.mkdir(parents=True, exist_ok=True)
        matrix_path.write_text(render_matrix(records), encoding="utf-8")
        notices_path.write_text(render_notices(records, RC_DIGEST), encoding="utf-8")
        provenance_path.parent.mkdir(parents=True, exist_ok=True)
        provenance_path.write_text(render_source_provenance(records), encoding="utf-8")
        json_write(source_plan_path, build_source_bundle_plan(records))
        json_write(closure_path, closure)
    errors = validate_outputs(sbom, closure, matrix_path, notices_path, provenance_path, source_plan_path, evidence_path)
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
