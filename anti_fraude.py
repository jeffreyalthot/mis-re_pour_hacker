#!/usr/bin/env python3
"""Outil simple pour détecter des comportements de fraude/hacking.

Ce script analyse un fichier CSV de journaux (ex: authentification, paiement)
et génère un rapport des activités suspectes avec des recommandations.
"""

from __future__ import annotations

import argparse
import csv
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path
from typing import Iterable, List


@dataclass(frozen=True)
class LogEntry:
    timestamp: datetime
    ip: str
    user: str
    action: str
    status: str
    amount: float
    country: str


@dataclass(frozen=True)
class Finding:
    ip: str
    user: str
    reason: str
    first_seen: datetime
    last_seen: datetime
    count: int


def parse_timestamp(value: str) -> datetime:
    return datetime.fromisoformat(value)


def load_logs(path: Path) -> List[LogEntry]:
    entries: List[LogEntry] = []
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        for row in reader:
            entries.append(
                LogEntry(
                    timestamp=parse_timestamp(row["timestamp"]),
                    ip=row["ip"],
                    user=row["user"],
                    action=row["action"],
                    status=row["status"],
                    amount=float(row.get("amount", "0") or 0),
                    country=row.get("country", "") or "unknown",
                )
            )
    return entries


def detect_bruteforce(entries: Iterable[LogEntry], window_minutes: int, threshold: int) -> List[Finding]:
    findings: List[Finding] = []
    sorted_entries = sorted(entries, key=lambda entry: entry.timestamp)
    for idx, entry in enumerate(sorted_entries):
        if entry.action != "login" or entry.status != "failure":
            continue
        window_start = entry.timestamp
        window_end = window_start + timedelta(minutes=window_minutes)
        window_attempts = [
            e
            for e in sorted_entries[idx:]
            if e.ip == entry.ip
            and e.action == "login"
            and e.status == "failure"
            and e.timestamp <= window_end
        ]
        if len(window_attempts) >= threshold:
            findings.append(
                Finding(
                    ip=entry.ip,
                    user=entry.user,
                    reason=f"{len(window_attempts)} échecs de connexion en {window_minutes} min",
                    first_seen=window_attempts[0].timestamp,
                    last_seen=window_attempts[-1].timestamp,
                    count=len(window_attempts),
                )
            )
    return deduplicate_findings(findings)


def detect_credential_stuffing(
    entries: Iterable[LogEntry],
    window_minutes: int,
    user_threshold: int,
) -> List[Finding]:
    findings: List[Finding] = []
    sorted_entries = sorted(entries, key=lambda entry: entry.timestamp)
    failures_by_ip: dict[str, List[LogEntry]] = {}
    for entry in sorted_entries:
        if entry.action == "login" and entry.status == "failure":
            failures_by_ip.setdefault(entry.ip, []).append(entry)

    for ip, failures in failures_by_ip.items():
        for idx, entry in enumerate(failures):
            window_start = entry.timestamp
            window_end = window_start + timedelta(minutes=window_minutes)
            window_attempts = [
                e for e in failures[idx:] if e.timestamp <= window_end
            ]
            distinct_users = {attempt.user for attempt in window_attempts}
            if len(distinct_users) >= user_threshold:
                findings.append(
                    Finding(
                        ip=ip,
                        user="multiple",
                        reason=(
                            f"Soupçon de credential stuffing: {len(distinct_users)} comptes visés "
                            f"en {window_minutes} min"
                        ),
                        first_seen=window_attempts[0].timestamp,
                        last_seen=window_attempts[-1].timestamp,
                        count=len(window_attempts),
                    )
                )
    return deduplicate_findings(findings)


def detect_payment_fraud(entries: Iterable[LogEntry], amount_threshold: float) -> List[Finding]:
    findings: List[Finding] = []
    for entry in entries:
        if entry.action != "payment" or entry.status != "success":
            continue
        if entry.amount >= amount_threshold:
            findings.append(
                Finding(
                    ip=entry.ip,
                    user=entry.user,
                    reason=f"Paiement élevé détecté ({entry.amount:.2f})",
                    first_seen=entry.timestamp,
                    last_seen=entry.timestamp,
                    count=1,
                )
            )
    return findings


def detect_geo_anomaly(entries: Iterable[LogEntry]) -> List[Finding]:
    findings: List[Finding] = []
    user_countries: dict[str, set[str]] = {}
    for entry in entries:
        if entry.action != "login" or entry.status != "success":
            continue
        countries = user_countries.setdefault(entry.user, set())
        if countries and entry.country not in countries:
            findings.append(
                Finding(
                    ip=entry.ip,
                    user=entry.user,
                    reason=f"Connexion depuis un nouveau pays ({entry.country})",
                    first_seen=entry.timestamp,
                    last_seen=entry.timestamp,
                    count=1,
                )
            )
        countries.add(entry.country)
    return findings


def deduplicate_findings(findings: List[Finding]) -> List[Finding]:
    unique: dict[tuple[str, str, str], Finding] = {}
    for finding in findings:
        key = (finding.ip, finding.user, finding.reason)
        if key in unique:
            existing = unique[key]
            combined = Finding(
                ip=finding.ip,
                user=finding.user,
                reason=finding.reason,
                first_seen=min(existing.first_seen, finding.first_seen),
                last_seen=max(existing.last_seen, finding.last_seen),
                count=max(existing.count, finding.count),
            )
            unique[key] = combined
        else:
            unique[key] = finding
    return list(unique.values())


def format_report(findings: List[Finding]) -> str:
    if not findings:
        return "Aucune activité suspecte détectée."
    lines = ["Rapport anti-fraude", "=" * 20]
    for finding in findings:
        lines.append(
            "- IP {ip} | Utilisateur {user} | {reason} | {count} occurrence(s) | {start} → {end}".format(
                ip=finding.ip,
                user=finding.user,
                reason=finding.reason,
                count=finding.count,
                start=finding.first_seen.isoformat(sep=" ", timespec="seconds"),
                end=finding.last_seen.isoformat(sep=" ", timespec="seconds"),
            )
        )
    lines.append("\nRecommandations:")
    lines.append("- Bloquer temporairement les IP listées.")
    lines.append("- Exiger une vérification MFA pour les comptes ciblés.")
    lines.append("- Surveiller les paiements élevés pendant 48h.")
    return "\n".join(lines)


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Analyse un fichier CSV et détecte des signaux de fraude/hacking.",
    )
    parser.add_argument("logfile", type=Path, help="Chemin vers le fichier CSV des journaux")
    parser.add_argument(
        "--window-minutes",
        type=int,
        default=10,
        help="Fenêtre (minutes) pour détecter les bruteforces (défaut: 10)",
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=5,
        help="Nombre d'échecs de connexion pour déclencher une alerte (défaut: 5)",
    )
    parser.add_argument(
        "--amount-threshold",
        type=float,
        default=500.0,
        help="Montant de paiement élevé à surveiller (défaut: 500)",
    )
    parser.add_argument(
        "--stuffing-window-minutes",
        type=int,
        default=15,
        help="Fenêtre (minutes) pour détecter le credential stuffing (défaut: 15)",
    )
    parser.add_argument(
        "--stuffing-user-threshold",
        type=int,
        default=4,
        help="Nombre de comptes distincts ciblés pour alerter (défaut: 4)",
    )
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    entries = load_logs(args.logfile)
    findings: List[Finding] = []
    findings.extend(detect_bruteforce(entries, args.window_minutes, args.threshold))
    findings.extend(
        detect_credential_stuffing(
            entries,
            args.stuffing_window_minutes,
            args.stuffing_user_threshold,
        )
    )
    findings.extend(detect_payment_fraud(entries, args.amount_threshold))
    findings.extend(detect_geo_anomaly(entries))
    report = format_report(deduplicate_findings(findings))
    print(report)


if __name__ == "__main__":
    main()
