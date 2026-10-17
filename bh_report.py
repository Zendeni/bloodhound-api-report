#!/usr/bin/env python3
"""Import BloodHound CE data and export a repeatable Cypher assessment.

Authentication is read from BH_TOKEN, or from BH_USERNAME/BH_PASSWORD. If a
username is supplied without a password, the password is requested securely.
No BloodHound credentials are written to the report.
"""

from __future__ import annotations

import argparse
import csv
import getpass
import json
import os
import sys
import time
import zipfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

import requests
import urllib3


DANGEROUS_RELATIONSHIPS = (
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "AllExtendedRights",
    "ForceChangePassword",
    "AddMember",
    "AddSelf",
    "AddKeyCredentialLink",
    "WriteSPN",
    "AdminTo",
    "CanRDP",
    "CanPSRemote",
    "ExecuteDCOM",
    "DCSync",
    "GetChanges",
    "GetChangesAll",
    "GetChangesInFilteredSet",
    "AllowedToAct",
    "AllowedToDelegate",
    "AddAllowedToAct",
    "WriteAccountRestrictions",
    "ReadLAPSPassword",
    "ReadGMSAPassword",
    "SQLAdmin",
)

# This is the AD traversal set used by BloodHound CE's built-in shortest-path
# searches. Restricting pathfinding to these edges avoids treating structural
# graph relationships as attack steps.
PATHFINDING_RELATIONSHIPS = (
    "Owns",
    "GenericAll",
    "GenericWrite",
    "WriteOwner",
    "WriteDacl",
    "MemberOf",
    "ForceChangePassword",
    "AllExtendedRights",
    "AddMember",
    "HasSession",
    "GPLink",
    "AllowedToDelegate",
    "CoerceToTGT",
    "AllowedToAct",
    "AdminTo",
    "CanPSRemote",
    "CanRDP",
    "ExecuteDCOM",
    "HasSIDHistory",
    "AddSelf",
    "DCSync",
    "ReadLAPSPassword",
    "ReadGMSAPassword",
    "DumpSMSAPassword",
    "SQLAdmin",
    "AddAllowedToAct",
    "WriteSPN",
    "AddKeyCredentialLink",
    "SyncLAPSPassword",
    "WriteAccountRestrictions",
    "WriteGPLink",
    "GoldenCert",
    "ADCSESC1",
    "ADCSESC3",
    "ADCSESC4",
    "ADCSESC6a",
    "ADCSESC6b",
    "ADCSESC9a",
    "ADCSESC9b",
    "ADCSESC10a",
    "ADCSESC10b",
    "ADCSESC13",
    "SyncedToADUser",
    "CoerceAndRelayNTLMToSMB",
    "CoerceAndRelayNTLMToADCS",
    "WriteOwnerLimitedRights",
    "OwnsLimitedRights",
    "ClaimSpecialIdentity",
    "CoerceAndRelayNTLMToLDAP",
    "CoerceAndRelayNTLMToLDAPS",
    "ContainsIdentity",
    "PropagatesACEsTo",
    "GPOAppliesTo",
    "CanApplyGPO",
    "HasTrustKeys",
    "ManageCA",
    "ManageCertificates",
    "Contains",
    "DCFor",
    "SameForestTrust",
    "SpoofSIDHistory",
    "AbuseTGTDelegation",
)


class BloodHoundError(RuntimeError):
    """A BloodHound API operation failed."""


@dataclass(frozen=True)
class QuerySpec:
    slug: str
    title: str
    purpose: str
    cypher: str


def cypher_string(value: str) -> str:
    """Return a safely quoted Cypher string literal."""

    escaped = value.replace("\\", "\\\\").replace("'", "\\'")
    return f"'{escaped}'"


def build_queries(principal: str, domain: str) -> list[QuerySpec]:
    user = cypher_string(principal)
    domain_name = cypher_string(domain)
    domain_admins = cypher_string(f"DOMAIN ADMINS@{domain}")
    dangerous = "|".join(DANGEROUS_RELATIONSHIPS)
    pathfinding = "|".join(PATHFINDING_RELATIONSHIPS)

    return [
        QuerySpec(
            "principal",
            "Principal record",
            "Confirms that the requested user was ingested.",
            f"MATCH (u:User {{name: {user}}}) RETURN u LIMIT 1",
        ),
        QuerySpec(
            "group_memberships",
            "Transitive group memberships",
            "Shows every group inherited through nested MemberOf relationships.",
            f"MATCH p=(u:User {{name: {user}}})-[:MemberOf*1..]->(g:Group) RETURN p LIMIT 1000",
        ),
        QuerySpec(
            "direct_relationships",
            "Direct outbound relationships",
            "Shows every relationship originating directly from the principal.",
            f"MATCH p=(u:User {{name: {user}}})-[r]->(target) RETURN p LIMIT 1000",
        ),
        QuerySpec(
            "effective_dangerous_rights",
            "Effective dangerous rights",
            "Finds dangerous rights held directly or through nested group membership.",
            (
                f"MATCH p=(u:User {{name: {user}}})-[:MemberOf*0..]->(via)"
                f"-[r:{dangerous}]->(target) RETURN p LIMIT 1000"
            ),
        ),
        QuerySpec(
            "computer_access",
            "Effective computer access",
            "Finds administration and remote-execution access held directly or through groups.",
            (
                f"MATCH p=(u:User {{name: {user}}})-[:MemberOf*0..]->(via)"
                "-[r:AdminTo|CanRDP|CanPSRemote|ExecuteDCOM|SQLAdmin]->(c:Computer) "
                "RETURN p LIMIT 1000"
            ),
        ),
        QuerySpec(
            "domain_admin_path",
            "Shortest path to Domain Admins",
            "Reproduces the common BloodHound path search for the selected principal.",
            (
                f"MATCH p=shortestPath((u:User {{name: {user}}})-[:{pathfinding}*1..]->"
                f"(g:Group {{name: {domain_admins}}})) RETURN p LIMIT 1000"
            ),
        ),
        QuerySpec(
            "asrep_roastable",
            "AS-REP roastable users",
            "Lists enabled users for which Kerberos pre-authentication is disabled.",
            (
                f"MATCH (u:User) WHERE u.domain = {domain_name} "
                "AND u.enabled = true AND u.dontreqpreauth = true "
                "RETURN u LIMIT 100"
            ),
        ),
        QuerySpec(
            "kerberoastable",
            "Kerberoastable users",
            "Lists enabled user accounts with service principal names.",
            (
                f"MATCH (u:User) WHERE u.domain = {domain_name} "
                "AND u.hasspn = true AND u.enabled = true "
                "AND NOT u.objectid ENDS WITH '-502' "
                "AND NOT COALESCE(u.gmsa, false) = true "
                "AND NOT COALESCE(u.msa, false) = true RETURN u LIMIT 100"
            ),
        ),
        QuerySpec(
            "weak_password_policy_flags",
            "Weak password-policy flags",
            "Lists enabled users with PasswordNotRequired or PasswordNeverExpires.",
            (
                f"MATCH (u:User) WHERE u.domain = {domain_name} AND u.enabled = true AND "
                "(u.passwordnotreqd = true OR u.pwdneverexpires = true) RETURN u LIMIT 1000"
            ),
        ),
        QuerySpec(
            "unconstrained_delegation",
            "Unconstrained delegation",
            "Lists principals trusted for unconstrained delegation.",
            (
                f"MATCH (n) WHERE n.domain = {domain_name} "
                "AND n.unconstraineddelegation = true RETURN n LIMIT 1000"
            ),
        ),
        QuerySpec(
            "domain_controllers",
            "Domain controllers",
            "Lists the domain controllers represented in the graph.",
            (
                "MATCH p=(c:Computer)-[:MemberOf*1..]->(g:Group) "
                f"WHERE c.domain = {domain_name} AND g.objectid ENDS WITH '-516' "
                "RETURN p LIMIT 1000"
            ),
        ),
    ]


class BloodHoundClient:
    def __init__(self, base_url: str, verify_tls: bool, timeout: float) -> None:
        self.base_url = base_url.rstrip("/")
        self.verify_tls = verify_tls
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update({"Accept": "application/json"})

    def authenticate(self, token: str | None, username: str | None, password: str | None) -> None:
        if token:
            self.session.headers["Authorization"] = f"Bearer {token}"
            return
        if not username:
            raise BloodHoundError(
                "authentication required: set BH_TOKEN, or provide --username/set BH_USERNAME"
            )
        if password is None:
            password = getpass.getpass(f"BloodHound password for {username}: ")
        response = self.request(
            "POST",
            "/api/v2/login",
            json_body={
                "login_method": "secret",
                "username": username,
                "secret": password,
            },
            authenticated=False,
        )
        try:
            session_token = response["data"]["session_token"]
        except (KeyError, TypeError) as exc:
            raise BloodHoundError("login succeeded but returned no session token") from exc
        self.session.headers["Authorization"] = f"Bearer {session_token}"

    def request(
        self,
        method: str,
        path: str,
        *,
        json_body: Any | None = None,
        data: Any | None = None,
        headers: dict[str, str] | None = None,
        authenticated: bool = True,
        allow_not_found: bool = False,
    ) -> Any:
        if authenticated and "Authorization" not in self.session.headers:
            raise BloodHoundError("attempted an authenticated request before login")
        url = f"{self.base_url}{path}"
        try:
            response = self.session.request(
                method,
                url,
                json=json_body,
                data=data,
                headers=headers,
                timeout=self.timeout,
                verify=self.verify_tls,
            )
        except requests.RequestException as exc:
            raise BloodHoundError(f"{method} {url} failed: {exc}") from exc

        if response.status_code == 404 and allow_not_found:
            return None
        if not response.ok:
            detail = response.text.strip()
            if len(detail) > 600:
                detail = detail[:600] + "..."
            raise BloodHoundError(
                f"{method} {path} returned HTTP {response.status_code}"
                + (f": {detail}" if detail else "")
            )
        if not response.content:
            return None
        try:
            return response.json()
        except requests.JSONDecodeError as exc:
            raise BloodHoundError(f"{method} {path} returned non-JSON data") from exc

    def datapipe_status(self) -> dict[str, Any]:
        response = self.request("GET", "/api/v2/datapipe/status")
        return dict(response.get("data") or {})

    def upload_zip(self, zip_path: Path, poll_interval: float, wait_timeout: float) -> int:
        baseline = self.datapipe_status()
        response = self.request("POST", "/api/v2/file-upload/start")
        try:
            upload_id = int(response["data"]["id"])
        except (KeyError, TypeError, ValueError) as exc:
            raise BloodHoundError("upload start returned no valid job ID") from exc

        print(f"[+] Upload job {upload_id}: sending {zip_path.name}", file=sys.stderr)
        with zip_path.open("rb") as handle:
            self.request(
                "POST",
                f"/api/v2/file-upload/{upload_id}",
                data=handle,
                headers={
                    "Content-Type": "application/zip",
                    "X-File-Upload-Name": zip_path.name,
                },
            )
        self.request("POST", f"/api/v2/file-upload/{upload_id}/end")
        self.wait_for_analysis(upload_id, baseline, poll_interval, wait_timeout)
        return upload_id

    def wait_for_analysis(
        self,
        upload_id: int,
        baseline: dict[str, Any],
        poll_interval: float,
        wait_timeout: float,
    ) -> None:
        deadline = time.monotonic() + wait_timeout
        baseline_analysis = baseline.get("last_complete_analysis_at")
        observed_busy = False
        last_status: str | None = None
        reported_queued = False

        while time.monotonic() < deadline:
            tasks_response = self.request(
                "GET", f"/api/v2/file-upload/{upload_id}/completed-tasks"
            )
            tasks = tasks_response.get("data") if isinstance(tasks_response, dict) else None
            if isinstance(tasks, list):
                errors = [
                    str(error)
                    for task in tasks
                    for error in (task.get("errors") or [])
                ]
                if errors:
                    raise BloodHoundError("ingest failed: " + "; ".join(errors))

            status_data = self.datapipe_status()
            status = str(status_data.get("status", "unknown"))
            if status != last_status:
                print(f"[+] Datapipe status: {status}", file=sys.stderr)
                last_status = status
            if status in {"ingesting", "analyzing", "purging"}:
                observed_busy = True

            analysis_time = status_data.get("last_complete_analysis_at")
            analysis_advanced = bool(analysis_time and analysis_time != baseline_analysis)
            tasks_complete = isinstance(tasks, list) and bool(tasks)
            if status == "idle" and not tasks_complete and not reported_queued:
                print(
                    "[+] Upload queued; waiting for the datapipe scheduler",
                    file=sys.stderr,
                )
                reported_queued = True
            if status == "idle" and tasks_complete and (analysis_advanced or observed_busy):
                print("[+] Ingest and graph analysis complete", file=sys.stderr)
                return
            time.sleep(poll_interval)

        raise BloodHoundError(
            f"timed out after {wait_timeout:g}s waiting for upload {upload_id} analysis"
        )

    def run_cypher(self, query: str) -> dict[str, Any]:
        response = self.request(
            "POST",
            "/api/v2/graphs/cypher",
            json_body={"query": query, "include_properties": True},
            # BloodHound CE returns 404, rather than an empty graph, when a
            # syntactically valid Cypher query has no matches.
            allow_not_found=True,
        )
        if response is None:
            return {"data": {"nodes": {}, "edges": [], "literals": []}}
        if not isinstance(response, dict) or not isinstance(response.get("data"), dict):
            raise BloodHoundError("Cypher endpoint returned an unexpected response")
        return response


def inspect_zip(zip_path: Path) -> dict[str, Any]:
    if not zip_path.is_file():
        raise BloodHoundError(f"collection ZIP does not exist: {zip_path}")
    try:
        with zipfile.ZipFile(zip_path) as archive:
            bad_file = archive.testzip()
            if bad_file:
                raise BloodHoundError(f"collection ZIP has a corrupt member: {bad_file}")
            files: list[dict[str, Any]] = []
            for info in archive.infolist():
                if info.is_dir():
                    continue
                entry: dict[str, Any] = {
                    "name": info.filename,
                    "compressed_bytes": info.compress_size,
                    "bytes": info.file_size,
                }
                if info.filename.lower().endswith(".json"):
                    with archive.open(info) as handle:
                        payload = json.load(handle)
                    meta = payload.get("meta") or {}
                    entry.update(
                        {
                            "type": meta.get("type"),
                            "count": meta.get("count"),
                            "version": meta.get("version"),
                        }
                    )
                files.append(entry)
    except (zipfile.BadZipFile, json.JSONDecodeError, OSError) as exc:
        raise BloodHoundError(f"cannot inspect collection ZIP {zip_path}: {exc}") from exc

    return {
        "path": str(zip_path.resolve()),
        "size_bytes": zip_path.stat().st_size,
        "file_count": len(files),
        "files": files,
    }


def scalar(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, sort_keys=True, separators=(",", ":"))
    if value is None:
        return ""
    return value


def normalize_nodes(graph_data: dict[str, Any]) -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    nodes = graph_data.get("nodes") or {}
    for node_id, node in nodes.items():
        row: dict[str, Any] = {
            "id": node_id,
            "label": node.get("label", ""),
            "kind": node.get("kind", ""),
            "object_id": node.get("objectId", ""),
            "is_tier_zero": node.get("isTierZero", False),
            "is_owned": node.get("isOwnedObject", False),
            "last_seen": node.get("lastSeen", ""),
        }
        for key, value in sorted((node.get("properties") or {}).items()):
            if key not in row:
                row[key] = scalar(value)
        rows.append(row)
    return sorted(rows, key=lambda row: (str(row.get("kind")), str(row.get("label"))))


def normalize_edges(graph_data: dict[str, Any]) -> list[dict[str, Any]]:
    nodes = graph_data.get("nodes") or {}
    rows: list[dict[str, Any]] = []
    for edge in graph_data.get("edges") or []:
        source_id = str(edge.get("source", ""))
        target_id = str(edge.get("target", ""))
        source = nodes.get(source_id) or {}
        target = nodes.get(target_id) or {}
        extra = {
            key: value
            for key, value in edge.items()
            if key not in {"source", "target", "kind", "label", "lastSeen"}
        }
        rows.append(
            {
                "source_id": source_id,
                "source": source.get("label", source_id),
                "relationship": edge.get("kind") or edge.get("label", ""),
                "target_id": target_id,
                "target": target.get("label", target_id),
                "last_seen": edge.get("lastSeen", ""),
                "properties": scalar(extra) if extra else "",
            }
        )
    return sorted(
        rows,
        key=lambda row: (
            str(row["source"]),
            str(row["relationship"]),
            str(row["target"]),
        ),
    )


def write_csv(path: Path, rows: list[dict[str, Any]], default_fields: Iterable[str]) -> None:
    fields = list(default_fields)
    extra_fields = sorted({key for row in rows for key in row if key not in fields})
    fields.extend(extra_fields)
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fields, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def markdown_cell(value: Any) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def markdown_table(headers: list[str], rows: list[list[Any]]) -> list[str]:
    output = [
        "| " + " | ".join(headers) + " |",
        "| " + " | ".join("---" for _ in headers) + " |",
    ]
    output.extend(
        "| " + " | ".join(markdown_cell(cell) for cell in row) + " |" for row in rows
    )
    return output


def inventory_markdown(inventory: dict[str, Any]) -> list[str]:
    lines = [
        "## Collection inventory",
        "",
        f"ZIP: `{inventory['path']}`  ",
        f"Archive members: {inventory['file_count']}  ",
        f"Archive size: {inventory['size_bytes']} bytes",
        "",
    ]
    rows = [
        [item.get("type") or item["name"], item.get("count", ""), item.get("version", "")]
        for item in inventory["files"]
    ]
    lines.extend(markdown_table(["Collection type", "Objects", "Schema"], rows))
    return lines


def create_report(
    output_dir: Path,
    principal: str,
    domain: str,
    api_url: str,
    inventory: dict[str, Any] | None,
    upload_id: int | None,
    results: list[tuple[QuerySpec, dict[str, Any]]],
    markdown_limit: int,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    generated_at = datetime.now(timezone.utc).isoformat()
    summary_queries: list[dict[str, Any]] = []

    for spec, response in results:
        query_dir = output_dir / spec.slug
        query_dir.mkdir(parents=True, exist_ok=True)
        graph_data = response["data"]
        nodes = normalize_nodes(graph_data)
        edges = normalize_edges(graph_data)
        (query_dir / "query.cypher").write_text(spec.cypher + "\n", encoding="utf-8")
        (query_dir / "raw.json").write_text(
            json.dumps(response, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        write_csv(
            query_dir / "nodes.csv",
            nodes,
            ["id", "label", "kind", "object_id", "is_tier_zero", "is_owned", "last_seen"],
        )
        write_csv(
            query_dir / "edges.csv",
            edges,
            [
                "source_id",
                "source",
                "relationship",
                "target_id",
                "target",
                "last_seen",
                "properties",
            ],
        )
        summary_queries.append(
            {
                "slug": spec.slug,
                "title": spec.title,
                "purpose": spec.purpose,
                "node_count": len(nodes),
                "edge_count": len(edges),
                "literal_count": len(graph_data.get("literals") or []),
                "nodes": nodes,
                "edges": edges,
            }
        )

    report_json = {
        "generated_at": generated_at,
        "bloodhound_url": api_url,
        "principal": principal,
        "domain": domain,
        "upload_id": upload_id,
        "inventory": inventory,
        "queries": summary_queries,
    }
    (output_dir / "report.json").write_text(
        json.dumps(report_json, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    if inventory is not None:
        (output_dir / "inventory.json").write_text(
            json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )

    lines = [
        "# BloodHound assessment",
        "",
        f"Generated: `{generated_at}`  ",
        f"Principal: `{principal}`  ",
        f"Domain: `{domain}`  ",
        f"BloodHound: `{api_url}`  ",
        f"Upload job: `{upload_id if upload_id is not None else 'not performed'}`",
        "",
        "> Results below come from BloodHound's analyzed graph. The ZIP inventory only validates collection contents.",
        "",
    ]
    if inventory is not None:
        lines.extend(inventory_markdown(inventory))
        lines.extend(["", ""])

    lines.extend(["## Query summary", ""])
    lines.extend(
        markdown_table(
            ["Query", "Nodes", "Edges"],
            [
                [item["title"], item["node_count"], item["edge_count"]]
                for item in summary_queries
            ],
        )
    )

    for item in summary_queries:
        lines.extend(["", "", f"## {item['title']}", "", item["purpose"], ""])
        if item["edges"]:
            edge_rows = [
                [edge["source"], edge["relationship"], edge["target"]]
                for edge in item["edges"][:markdown_limit]
            ]
            lines.extend(markdown_table(["Source", "Relationship", "Target"], edge_rows))
            if len(item["edges"]) > markdown_limit:
                lines.append(f"\n_Truncated to {markdown_limit} edges; see the query CSV._")
        elif item["nodes"]:
            node_rows = [
                [node["label"], node["kind"], node["object_id"]]
                for node in item["nodes"][:markdown_limit]
            ]
            lines.extend(markdown_table(["Node", "Kind", "Object ID"], node_rows))
            if len(item["nodes"]) > markdown_limit:
                lines.append(f"\n_Truncated to {markdown_limit} nodes; see the query CSV._")
        else:
            lines.append("_No matching graph data._")

    report_path = output_dir / "report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def create_offline_report(output_dir: Path, inventory: dict[str, Any]) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    (output_dir / "inventory.json").write_text(
        json.dumps(inventory, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    lines = [
        "# BloodHound collection inventory",
        "",
        "> Offline mode does not calculate nested group rights or attack paths. Import into BloodHound and run the API assessment for security findings.",
        "",
    ]
    lines.extend(inventory_markdown(inventory))
    report_path = output_dir / "report.md"
    report_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return report_path


def parse_args(argv: list[str]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload BloodHound CE collection data, run Cypher checks, and export reports."
    )
    parser.add_argument(
        "--url",
        default=os.environ.get("BH_URL"),
        help="BloodHound CE base URL (default: BH_URL; required except in offline mode)",
    )
    parser.add_argument(
        "--username",
        default=os.environ.get("BH_USERNAME"),
        help="BloodHound username (default: BH_USERNAME)",
    )
    parser.add_argument(
        "--zip",
        dest="zip_path",
        type=Path,
        help="SharpHound/bloodhound-python ZIP to validate and upload",
    )
    parser.add_argument(
        "--no-upload",
        action="store_true",
        help="inspect --zip but query the graph without uploading it",
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="only validate/inventory --zip; do not contact BloodHound",
    )
    parser.add_argument(
        "--principal",
        help="user to assess, as NAME@DOMAIN or NAME with --domain (required except offline)",
    )
    parser.add_argument(
        "--domain",
        help="AD DNS domain; defaults to the suffix of --principal",
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("loot/bloodhound/report"),
        help="report directory (default: loot/bloodhound/report)",
    )
    parser.add_argument("--insecure", action="store_true", help="disable HTTPS certificate checks")
    parser.add_argument("--request-timeout", type=float, default=60.0)
    parser.add_argument("--wait-timeout", type=float, default=600.0)
    parser.add_argument("--poll-interval", type=float, default=3.0)
    parser.add_argument("--markdown-limit", type=int, default=50)
    args = parser.parse_args(argv)

    if args.offline and args.zip_path is None:
        parser.error("--offline requires --zip")
    if args.offline and args.no_upload:
        parser.error("--offline and --no-upload are redundant; choose one")
    if not args.offline and not args.url:
        parser.error("--url or BH_URL is required")
    if not args.offline and not args.principal:
        parser.error("--principal is required except in offline mode")
    if args.poll_interval <= 0 or args.request_timeout <= 0 or args.wait_timeout <= 0:
        parser.error("timeouts and polling interval must be positive")
    if args.markdown_limit <= 0:
        parser.error("--markdown-limit must be positive")
    return args


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv or sys.argv[1:])
    inventory = inspect_zip(args.zip_path) if args.zip_path else None
    if args.offline:
        report_path = create_offline_report(args.output, inventory)
        print(f"[+] Offline inventory written to {report_path}")
        return 0

    principal = args.principal.strip().upper()
    requested_domain = args.domain.strip().upper() if args.domain else None
    if not principal:
        raise BloodHoundError("--principal cannot be empty")
    if "@" in principal:
        principal_name, principal_domain = principal.rsplit("@", 1)
        if not principal_name or not principal_domain:
            raise BloodHoundError("--principal must use NAME@DOMAIN format")
        if requested_domain and requested_domain != principal_domain:
            raise BloodHoundError(
                f"--domain {requested_domain} does not match the principal domain {principal_domain}"
            )
        domain = principal_domain
    else:
        if not requested_domain:
            raise BloodHoundError("a bare --principal requires --domain")
        domain = requested_domain
        principal = f"{principal}@{domain}"

    if args.insecure:
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
    client = BloodHoundClient(args.url, not args.insecure, args.request_timeout)
    client.authenticate(
        os.environ.get("BH_TOKEN"),
        args.username,
        os.environ.get("BH_PASSWORD"),
    )

    upload_id = None
    if args.zip_path and not args.no_upload:
        upload_id = client.upload_zip(
            args.zip_path.resolve(), args.poll_interval, args.wait_timeout
        )

    results: list[tuple[QuerySpec, dict[str, Any]]] = []
    for spec in build_queries(principal, domain):
        print(f"[+] Query: {spec.title}", file=sys.stderr)
        results.append((spec, client.run_cypher(spec.cypher)))

    report_path = create_report(
        args.output,
        principal,
        domain,
        args.url,
        inventory,
        upload_id,
        results,
        args.markdown_limit,
    )
    print(f"[+] Report written to {report_path}")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (BloodHoundError, OSError) as exc:
        print(f"[-] {exc}", file=sys.stderr)
        raise SystemExit(1)
