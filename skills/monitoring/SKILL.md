---
name: monitoring
description: Shodan network alerts, triggers and notifiers
version: 0.1.0
author: hermes-plugin-shodan
license: MIT
metadata:
  hermes:
    tags: [shodan, monitoring, alerts, triggers, asm, security]
---

# Shodan network monitoring

Requires the `full` tool profile: `hermes shodan profile full`.

A Shodan alert is a standing watch on a set of IPs. Shodan re-scans them as
part of its normal crawl and fires when a trigger condition matches. It is the
difference between knowing your exposure today and noticing when it changes.

## Two-step setup, and the trap in it

Creating an alert does **not** start monitoring anything. A new alert has no
triggers, so it will never fire. This catches everyone once.

```
shodan_alert(action="create", name="Corp external", ips="203.0.113.0/24")
shodan_alert(action="enable_trigger", alert_id="<id>", trigger="new_service")
```

The second call is the one that turns it on.

## Triggers

Fetch the current list with `shodan_alert(action="triggers")`, which is free
and authoritative. As of now there are fourteen:

| Trigger | Fires when |
|---|---|
| `any` | Any change at all on a watched host |
| `new_service` | A port opens that was not open before |
| `vulnerable` | A host matches a verified known vulnerability |
| `vulnerable_unverified` | A host matches an inferred vulnerability |
| `open_database` | An unauthenticated database becomes reachable |
| `ssl_expired` | A certificate expires |
| `end_of_life` | Software past its support date is detected |
| `industrial_control_system` | An ICS or SCADA service appears |
| `iot` | An IoT device appears |
| `malware` | Malware or a C2 indicator is detected |
| `internet_scanner` | The host starts behaving like a scanner |
| `uncommon` | An unusual service appears |
| `uncommon_plus` | A stricter version of the same |
| `ai` | An AI-related service is detected |

For an organization's own external range, `new_service`, `open_database`,
`ssl_expired` and `vulnerable` cover most of what matters without generating
noise. `any` sounds thorough and in practice buries the signal.

## Notifiers

Triggers decide when an alert fires. Notifiers decide where it goes. Every
account has a `default` email notifier already attached. The API supports
email, phone, Slack (`webhook_url`), Telegram (`chat_id` and `token`),
PagerDuty (`routing_key`), a generic webhook (`url`), and Gitter.

This plugin exposes alert and trigger management but not notifier creation.
Set up notifiers at https://account.shodan.io, then attach them to alerts
there. Wiring a webhook is a durable change to someone's alerting path and is
better done deliberately in a UI than through a conversation.

## Limits

Monitored IPs count against the plan's allowance, which
`shodan_account` reports. Membership allows 16 monitored IPs, Freelancer 5120,
Small Business 65536, Corporate 327680. A `/24` consumes 256 of them, so a
Membership account cannot monitor even one full class C.

Check the allowance before creating something that will not fit:

```
shodan_account()
```

## Housekeeping

```
shodan_alert(action="list")                      # what exists
shodan_alert(action="info", alert_id="<id>")     # one alert in detail
shodan_alert(action="delete", alert_id="<id>")   # remove it
```

Alerts outlive the conversation that created them. They keep consuming the
monitored-IP allowance until deleted, and they keep sending notifications to
whoever the notifier points at. Confirm with the user before creating or
deleting one, and prefer setting `expires` on anything meant to be temporary.
