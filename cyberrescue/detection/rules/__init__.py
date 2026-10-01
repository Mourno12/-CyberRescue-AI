"""Shipped detection rules. Order is irrelevant: the registry sorts by rule id."""

from cyberrescue.detection.rules.auth import FailedThenSuccess, RepeatedFailures
from cyberrescue.detection.rules.lateral import RemoteAuthToMultipleHosts

ALL_RULES: list[type] = [
    FailedThenSuccess, RepeatedFailures,
    RemoteAuthToMultipleHosts,
]
