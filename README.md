# unifi-wazuh
Custom Wazuh decoders and rules for UniFi Network devices. Parses CEF (Common Event Format) syslog events from UniFi OS and UniFi Network applications.

Tested using UniFi OS 4.4.9 + UniFi Network 10.0.162 + Wazuh 4.14.

## Events Covered

| Rule ID | Event | Level |
|---------|-------|-------|
| 100102 | Base UniFi event (silent parent) | 0 |
| 100103 | UniFi Console event | 3 |
| 100104 | Traffic Internal Allow (LAN→LAN) | 3 |
| 100105 | Traffic External Allow (LAN→WAN) | 3 |
| 100106 | Traffic Internal Block (LAN→LAN) | 7 |
| 100107 | Traffic External Block (LAN→WAN) | 7 |
| 100110 | Configuration Change | 8 |
| 100111 | IPS Threat Detected | 10 |
| 100112 | WiFi Client Connected | 3 |
| 100113 | WiFi Client Disconnected | 3 |

Rules include compliance mappings for PCI DSS, NIST 800-53, and HIPAA.

## Installation

Copy the decoder and rules files to your Wazuh manager:

```bash
cp unifi_decoders.xml /var/ossec/etc/decoders/
cp unifi_rules.xml /var/ossec/etc/rules/
```

Restart the Wazuh manager:

```bash
systemctl restart wazuh-manager
```

## Testing

Use `wazuh-logtest` to validate decoder and rule matching:

```bash
/var/ossec/bin/wazuh-logtest
```

Use `wazuh-analysisd` to validate the decoders and rules:
```bash
/var/ossec/bin/wazuh-analysisd -t
```

Paste a sample UniFi syslog line to verify the correct decoder and rules match.

## Changelog

2025-12-22:
* Added compliance mappings to rules (PCI DSS, NIST 800-53, HIPAA)
* Renumbered rule IDs from 100002-100007 to 100102-100113
* Adjusted rule levels: base rule now silent (level 0), allow rules level 3, block rules level 7
* Added new rules: config change detection (100110), IPS threat detection (100111), WiFi client connect/disconnect (100112/100113)
* Updated tested versions to UniFi OS 4.4.9, UniFi Network 10.0.162, Wazuh 4.14

2025-12-12:
* Small fix to base in severity field

2025-10-25:
* Divided syslog traffic events based on firewall action
* Ordered key values by section
* Preliminary fields for Threat Detected and Blocked events
