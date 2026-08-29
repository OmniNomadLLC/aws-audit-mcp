"""Aggregated posture audit: run every registered check and score the account.

This module makes no AWS calls itself; it discovers the other tool modules at
call time and delegates to them, so new checks are included automatically.
"""

import importlib
import pkgutil

from aws_audit_mcp.common import READ_ONLY, report

# severity -> weight used by the posture score
_WEIGHTS = {"LOW": 1, "MEDIUM": 2, "HIGH": 5, "CRITICAL": 10}


def _discover_checks() -> list:
    """Collect every audit_/account_ callable defined in a sibling tool module."""
    from aws_audit_mcp import tools

    checks = []
    for info in pkgutil.iter_modules(tools.__path__):
        if info.name.startswith("_") or info.name == "full":
            continue
        module = importlib.import_module(f"{tools.__name__}.{info.name}")
        for name, obj in sorted(vars(module).items()):
            if (
                callable(obj)
                and (name.startswith("audit_") or name.startswith("account_"))
                and getattr(obj, "__module__", None) == module.__name__
            ):
                checks.append(obj)
    return checks


def _grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 60:
        return "C"
    if score >= 40:
        return "D"
    return "F"


def audit_full_posture() -> dict:
    """Run every registered audit check with default arguments and aggregate
    the results into a single account posture report.

    Discovers all audit_*/account_* functions in the tool modules and runs each
    one; a failing check is recorded in `errors` and never aborts the rest.
    Returns the standard {check, ok, findings, scanned} envelope where findings
    is the concatenation of every sub-report's findings and scanned is the
    number of checks run, plus severity_counts (LOW/MEDIUM/HIGH/CRITICAL),
    posture_score, grade, checks_run, and errors. The score is weighted:
    each CRITICAL finding costs 10 points, HIGH 5, MEDIUM 2, LOW 1, and
    posture_score = max(0, 100 - total weight). Grades: A >= 90, B >= 75,
    C >= 60, D >= 40, else F.
    """
    all_findings = []
    checks_run = []
    errors = []
    for func in _discover_checks():
        name = f"{func.__module__.rsplit('.', 1)[-1]}.{func.__name__}"
        try:
            sub = func()
        except Exception as exc:
            errors.append({"check": name, "error": str(exc)})
            continue
        checks_run.append(func.__name__)
        all_findings.extend(sub.get("findings", []))

    severity_counts = {sev: 0 for sev in _WEIGHTS}
    for f in all_findings:
        sev = f.get("severity")
        if sev in severity_counts:
            severity_counts[sev] += 1
    total_weight = sum(_WEIGHTS[sev] * count for sev, count in severity_counts.items())
    posture_score = max(0, 100 - total_weight)

    return report(
        "full.posture",
        all_findings,
        scanned=len(checks_run) + len(errors),
        severity_counts=severity_counts,
        posture_score=posture_score,
        grade=_grade(posture_score),
        checks_run=checks_run,
        errors=errors,
    )


def register(mcp):
    mcp.tool(annotations=READ_ONLY)(audit_full_posture)
