#!/bin/sh
# Routing unit tests: every alert in observability/prometheus/alerts.yml, with the
# labels Prometheus attaches, must reach the intended receiver.
#
#   docker run --rm -v "$PWD/observability/alertmanager:/etc/alertmanager:ro" \
#     --entrypoint sh prom/alertmanager:v0.34.1 /etc/alertmanager/routes.test.sh
set -eu

CONFIG="${CONFIG:-/etc/alertmanager/alertmanager.yml}"
failures=0

expect() {
  receiver="$1"
  shift
  if amtool config routes test --config.file="$CONFIG" --verify.receivers="$receiver" "$@" >/dev/null; then
    echo "ok   $receiver <- $*"
  else
    echo "FAIL $receiver <- $* (got: $(amtool config routes test --config.file="$CONFIG" "$@"))"
    failures=$((failures + 1))
  fi
}

# The rules as written, with the labels each expression keeps.
expect pager alertname=TargetDown severity=critical job=orders-service instance=orders-service:8081
expect pager alertname=GatewayErrorRate severity=critical router=orders@file
expect platform alertname=HighServerErrorRate severity=warning job=auth-service
expect platform alertname=SlowRequests severity=warning job=orders-service
expect security alertname=RefreshTokenReuse severity=warning category=security job=auth-service instance=auth-service:9100
expect security alertname=LoginBruteForce severity=warning category=security

# Security wins over severity, and unknown alerts still reach a human.
expect security alertname=SomeFutureAttack severity=critical category=security
expect platform alertname=Unclassified

if [ "$failures" -ne 0 ]; then
  echo "$failures routing expectation(s) failed"
  exit 1
fi
echo "all routing expectations hold"
