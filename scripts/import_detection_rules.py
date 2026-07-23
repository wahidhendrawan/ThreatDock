#!/usr/bin/env python3
"""Import Sigma detection rules as ThreatDock alerts/indicators.

Fetches rules from Detection-Rules repo and outputs a JSON file ready for
ThreatDock import (matching the ThreatDock alert schema).

Usage:
    python scripts/import_detection_rules.py --source detection-rules
    python scripts/import_detection_rules.py --repo-url https://github.com/wahidhendrawan/Detection-Rules
    python scripts/import_detection_rules.py --output imported_alerts.json
    python scripts/import_detection_rules.py --dry-run

Output: JSON array matching ThreatDock alert ingestion format.
"""

from __future__ import annotations

import argparse
import json
import re
import subprocess
import sys
import tempfile
import yaml
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

DEFAULT_REPO = "https://github.com/wahidhendrawan/Detection-Rules.git"


def fetch_repo(repo_url: str) -> Path:
    """Clone Detection-Rules and return local path."""
    tmpdir = Path(tempfile.mkdtemp(prefix="td-import-"))
    url = repo_url or DEFAULT_REPO
    print(f"[*] Cloning {url} ...")
    try:
        subprocess.run(
            ["git", "clone", "--depth", "1", url, str(tmpdir)],
            check=True, capture_output=True, timeout=60,
        )
    except subprocess.CalledProcessError as exc:
        print(f"[-] Clone failed: {exc.stderr.decode()}", file=sys.stderr)
        sys.exit(1)
    return tmpdir


def parse_sigma(path: Path) -> dict[str, Any] | None:
    try:
        rule = yaml.safe_load(path.read_text(encoding="utf-8"))
        return rule if isinstance(rule, dict) and "title" in rule else None
    except Exception:
        return None


def map_to_alert(rule: dict[str, Any], source_path: str) -> dict[str, Any]:
    """Map Sigma rule to ThreatDock alert format."""
    tags = rule.get("tags", [])
    mitre = [t.replace("attack.", "").upper() for t in tags if t.startswith("attack.")]

    sev = rule.get("level", "medium")
    severity = {"critical": "Critical", "high": "High", "medium": "Medium", "low": "Low"}.get(sev, "Medium")

    return {
        "title": rule.get("title", "Untitled Rule"),
        "description": rule.get("description", ""),
        "severity": severity,
        "source": "Detection-Rules Auto-Import",
        "source_path": source_path,
        "mitre_attack_tags": mitre,
        "tags": [t for t in tags if not t.startswith("attack.")],
        "references": rule.get("references", []),
        "status": "new",
        "logsource_product": rule.get("logsource", {}).get("product", ""),
        "logsource_category": rule.get("logsource", {}).get("category", ""),
        "detection_condition": str(rule.get("detection", {}).get("condition", "")),
        "imported_at": datetime.now(timezone.utc).isoformat(),
        "author": rule.get("author", ""),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="Import Detection-Rules → ThreatDock alerts")
    parser.add_argument("--source", choices=["detection-rules"], default="detection-rules")
    parser.add_argument("--repo-url", default=DEFAULT_REPO)
    parser.add_argument("--output", default="imported_alerts.json")
    parser.add_argument("--max", type=int, default=200, help="Max alerts to import")
    parser.add_argument("--dry-run", action="store_true", help="Preview only")
    args = parser.parse_args()

    repo = fetch_repo(args.repo_url)
    print(f"[*] Scanning {repo} for Sigma, Elastic, and Splunk rules...")

    formats = {
        "sigma": list(repo.rglob("sigma/**/*.yml")) + list(repo.rglob("sigma/**/*.yaml")),
        "elastic": list(repo.rglob("elastic/**/*.ndjson")),
        "splunk": list(repo.rglob("splunk/**/*.spl")),
        "kql": list(repo.rglob("microsoft-sentinel/**/*.kql")),
    }

    total_files = sum(len(v) for v in formats.values())
    print(f"  Found {total_files} rule files across {len(formats)} formats")

    alerts = []
    limit = args.max

    for fmt_name, files in formats.items():
        if limit <= 0:
            break
        for f in files[:limit]:
            if fmt_name == "sigma":
                rule = parse_sigma(f)
                if rule:
                    rel = f.relative_to(repo)
                    alert = map_to_alert(rule, str(rel))
                    alerts.append(alert)
                    limit -= 1
            elif fmt_name in ("elastic", "splunk", "kql"):
                try:
                    content = f.read_text(encoding="utf-8", errors="ignore")[:200]
                    # Extract title from content
                    title_match = re.search(r'"title"\s*:\s*"([^"]+)"', content) or \
                                  re.search(r'title:\s*([^\n]+)', content) or \
                                  re.search(r'//\s*([A-Z][^,\n]+)', content)
                    title = title_match.group(1).strip() if title_match else f.name
                    rel = f.relative_to(repo)
                    alerts.append({
                        "title": title,
                        "description": f"Auto-imported {fmt_name} rule from {rel}",
                        "severity": "Medium",
                        "source": f"Detection-Rules ({fmt_name})",
                        "source_path": str(rel),
                        "mitre_attack_tags": [],
                        "tags": ["auto-imported", fmt_name],
                        "references": [],
                        "status": "new",
                        "imported_at": datetime.now(timezone.utc).isoformat(),
                    })
                    limit -= 1
                except Exception:
                    pass
            if limit <= 0:
                break

    if args.dry_run:
        print(f"\n[Dry-run] Would import {len(alerts)} alerts. First 3:")
        for a in alerts[:3]:
            print(f"  - {a['title']} [{a['severity']}] ({a['source_path']})")
        print(f"  ... and {len(alerts) - 3} more")
        return 0

    out_path = Path(args.output)
    out_path.write_text(json.dumps(alerts, indent=2), encoding="utf-8")
    print(f"\n✅ Imported {len(alerts)} detection rules as ThreatDock alerts")
    print(f"   Output: {out_path}")
    print(f"   Import via: POST /api/intelligence/indicators/import (or manual review)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
