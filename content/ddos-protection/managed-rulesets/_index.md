---
pcx_content_type: concept
title: Managed rulesets
layout: single
weight: 5
---

# Managed rulesets

The DDoS Attack Protection managed rulesets provide comprehensive protection against a [variety of DDoS attacks](/ddos-protection/about/attack-coverage/) across L3/4 (network layer) and L7 (application layer) of the [OSI model](https://www.cloudflare.com/learning/ddos/glossary/open-systems-interconnection-model-osi/).

The available managed rulesets are:

{{<definitions>}}

* **[HTTP DDoS Attack Protection](/ddos-protection/managed-rulesets/http/)**

    * This ruleset includes rules to detect and mitigate DDoS attacks over HTTP and HTTPS.

* **[Network-layer DDoS Attack Protection](/ddos-protection/managed-rulesets/network/)**

    * This ruleset includes rules to detect and mitigate DDoS attacks on L3/4 of the OSI model such as UDP floods, SYN-ACK reflection attacks, SYN Floods, and DNS floods.

{{</definitions>}}

---

## Proactive false positive detection for new rules

{{<Aside type="note">}}
Only available on Business and Enterprise plans.
{{</Aside>}}

When Cloudflare creates a new managed rule, we check the rule impact against the traffic of Business and Enterprise zones while the rule is not blocking traffic yet.

If a [false positive](/ddos-protection/managed-rulesets/adjust-rules/false-positive/) is detected, we proactively reach out to the affected customers and help them make configuration changes (for example, to lower the sensitivity level of the new rule) before the rule starts mitigating traffic. This prevents the new rule from causing service disruptions and outages to your Internet properties.
