"""
compliance_reporting.adapters
=============================
Adapters that translate a canonical Furix compliance report into the shapes
external consumers expect. Currently: the secureguard dashboard's
`ComplianceFramework[]` contract.
"""

from .dashboard import report_to_frameworks, report_to_summary

__all__ = ["report_to_frameworks", "report_to_summary"]
