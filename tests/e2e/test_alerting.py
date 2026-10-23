"""Alert routing through the real Prometheus -> Alertmanager -> receiver path.

The first test fires a production rule (RefreshTokenReuse) by replaying a refresh
token and waits for the notification in the local alert sink. The others inject
synthetic alerts straight into Alertmanager, labelled with a per-run job so they
never collide with real ones, to check severity routing, inhibition and grouping.
"""

from __future__ import annotations

import uuid
from datetime import UTC, datetime, timedelta
from typing import Any

import httpx
import pytest

from conftest import eventually, register_and_login, setting

ALERTMANAGER_URL = setting(
    "ALERTMANAGER_URL", "http://localhost:" + setting("ALERTMANAGER_PORT", "9093")
)
ALERT_SINK_URL = setting("ALERT_SINK_URL", "http://localhost:" + setting("ALERT_SINK_PORT", "9097"))


def notifications(receiver: str) -> list[dict[str, Any]]:
    response = httpx.get(
        f"{ALERT_SINK_URL}/notifications", params={"receiver": receiver}, timeout=10
    )
    response.raise_for_status()
    items: list[dict[str, Any]] = response.json()
    return items


def delivered(receiver: str, **labels: str) -> list[dict[str, Any]]:
    """Firing alerts delivered to `receiver` whose labels include `labels`."""
    return [
        alert
        for item in notifications(receiver)
        for alert in item["payload"]["alerts"]
        if alert["status"] == "firing" and labels.items() <= alert["labels"].items()
    ]


def inject(*alerts: dict[str, str], minutes: int = 5) -> None:
    now = datetime.now(UTC)
    body = [
        {
            "labels": labels,
            "annotations": {"summary": "synthetic alert from the e2e suite"},
            "startsAt": now.isoformat(),
            "endsAt": (now + timedelta(minutes=minutes)).isoformat(),
        }
        for labels in alerts
    ]
    response = httpx.post(f"{ALERTMANAGER_URL}/api/v2/alerts", json=body, timeout=10)
    assert response.status_code == 200, response.text


def alertmanager_state(job: str) -> dict[str, dict[str, Any]]:
    response = httpx.get(
        f"{ALERTMANAGER_URL}/api/v2/alerts",
        params={"filter": f'job="{job}"', "inhibited": "true", "silenced": "true"},
        timeout=10,
    )
    response.raise_for_status()
    return {alert["labels"]["alertname"]: alert["status"] for alert in response.json()}


@pytest.fixture
def job() -> str:
    return f"e2e-{uuid.uuid4().hex[:12]}"


class TestAlertRouting:
    def test_prometheus_delivers_alerts_to_alertmanager(self) -> None:
        def connected() -> None:
            prometheus = setting(
                "PROMETHEUS_URL", "http://localhost:" + setting("PROMETHEUS_PORT", "9090")
            )
            body = httpx.get(f"{prometheus}/api/v1/alertmanagers", timeout=10).json()
            urls = [am["url"] for am in body["data"]["activeAlertmanagers"]]
            assert urls == ["http://alertmanager:9093/api/v2/alerts"]

        eventually(connected)

    def test_a_replayed_refresh_token_reaches_the_security_receiver(
        self, gateway: httpx.Client
    ) -> None:
        account = register_and_login(gateway)
        url = "/api/v1/auth/token/refresh/"
        assert gateway.post(url, json={"refresh_token": account.refresh_token}).status_code == 200
        assert gateway.post(url, json={"refresh_token": account.refresh_token}).status_code == 401

        # scrape (10 s) + rule evaluation (10 s) + the security route's group_wait (10 s)
        def paged() -> None:
            alerts = delivered("security", alertname="RefreshTokenReuse")
            assert alerts, "no RefreshTokenReuse notification yet"
            assert alerts[-1]["labels"]["severity"] == "warning"
            assert alerts[-1]["labels"]["category"] == "security"

        eventually(paged, timeout=120, interval=5)
        assert not delivered("platform", alertname="RefreshTokenReuse"), "routed once, not twice"

    def test_critical_alerts_page_and_silence_that_services_warnings(self, job: str) -> None:
        inject(
            {"alertname": "TargetDown", "severity": "critical", "job": job},
            {"alertname": "HighServerErrorRate", "severity": "warning", "job": job},
        )

        def inhibited() -> None:
            state = alertmanager_state(job)
            assert state["TargetDown"]["state"] == "active"
            assert state["HighServerErrorRate"]["state"] == "suppressed"
            assert state["HighServerErrorRate"]["inhibitedBy"], "inhibited by TargetDown"

        def paged() -> None:
            assert delivered("pager", alertname="TargetDown", job=job)

        eventually(inhibited)
        eventually(paged, timeout=60, interval=3)
        assert not delivered("platform", job=job), "the inhibited warning is never sent"

    def test_a_critical_alert_without_a_job_cannot_silence_security_alerts(self, job: str) -> None:
        router = f"{job}@file"
        inject(
            {"alertname": "GatewayErrorRate", "severity": "critical", "router": router},
            {"alertname": "E2ESecurityProbe", "severity": "warning", "category": "security"},
            {"alertname": "E2EWarningWithoutJob", "severity": "warning", "router": router},
        )

        def routed() -> None:
            assert delivered("pager", alertname="GatewayErrorRate", router=router)
            assert delivered("security", alertname="E2ESecurityProbe")
            assert delivered("platform", alertname="E2EWarningWithoutJob", router=router)

        eventually(routed, timeout=90, interval=3)

    def test_security_alerts_are_grouped_by_alertname(self, job: str) -> None:
        alertname = f"E2EGrouping{uuid.uuid4().hex[:8]}"
        inject(
            *(
                {
                    "alertname": alertname,
                    "severity": "warning",
                    "category": "security",
                    "instance": f"auth-{n}",
                    "job": job,
                }
                for n in range(3)
            )
        )

        def grouped() -> None:
            batches = [
                item
                for item in notifications("security")
                if item["payload"]["groupLabels"] == {"alertname": alertname}
            ]
            assert batches, "not delivered yet"
            assert len(batches[0]["payload"]["alerts"]) == 3, "one notification for the group"

        eventually(grouped, timeout=60, interval=3)
