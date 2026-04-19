# unifi-wazuh
Custom Wazuh decoders and rules for UniFi Network devices. Parses CEF (Common Event Format) syslog events and hostapd device syslog from UniFi OS and UniFi Network applications.

Tested using UniFi OS 5.0.16 + UniFi Network 10.2.105 + Wazuh 4.14.

## Events Covered

### CEF Event Rules

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
| 100114 | Admin Accessed UniFi | 5 |
| 100115 | Device Adopted | 5 |
| 100116 | Device Offline | 8 |
| 100117 | WiFi Client Roaming | 3 |
| 100118 | Wired Client Connected | 3 |
| 100119 | Wired Client Disconnected | 3 |
| 100120 | Honeypot Triggered | 12 |
| 100121 | Blocked by Firewall (CEF) | 10 |
| 100122 | WAN Failover | 8 |
| 100123 | High Latency Detected | 5 |
| 100124 | Packet Loss Detected | 7 |
| 100125 | Insufficient PoE Output | 7 |
| 100126 | AP Underpowered | 5 |
| 100127 | PoE Availability Exceeded | 7 |
| 100128 | IPS Threat from Internal Host | 13 |
| 100199 | Unmatched CEF Event (catch-all) | 3 |

### Hostapd Rules

| Rule ID | Event | Level |
|---------|-------|-------|
| 100200 | Hostapd grouping (silent parent) | 0 |
| 100201 | STA Associated | 3 |
| 100202 | STA Disassociated | 3 |
| 100203 | RADIUS Auth Success | 5 |
| 100204 | RADIUS Auth Failed | 8 |

### Correlation / Frequency Rules

| Rule ID | Triggers On | Threshold | Level |
|---------|------------|-----------|-------|
| 100150 | LAN block (100106) | 10 in 2 min, same src | 10 |
| 100151 | WAN block (100107) | 10 in 2 min, same src | 10 |
| 100152 | IPS threat (100111) | 5 in 5 min | 13 |
| 100153 | WiFi disconnect (100113) | 8 in 1 min, same client | 8 |
| 100210 | RADIUS fail (100204) | 5 in 2 min, same MAC | 10 |

Rules include compliance mappings for PCI DSS, NIST 800-53, HIPAA, and MITRE ATT&CK.

## Installation

Copy the decoder and rules files to your Wazuh manager:

```bash
cp unifi_decoders.xml /var/ossec/etc/decoders/
cp unifi_rules.xml /var/ossec/etc/rules/
```

Set the decoder and rules permissions appropriately:

```bash
chown wazuh:wazuh /var/ossec/etc/decoders/unifi_decoders.xml && chmod 660 /var/ossec/etc/decoders/unifi_decoders.xml
chown wazuh:wazuh /var/ossec/etc/rules/unifi_rules.xml && chmod 660 /var/ossec/etc/rules/unifi_rules.xml
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

2026-04-19:
* Added support for UniFi OS 5.0.16 / Network 10.2.105
* IPv6 support in CEF `src=`, `dst=`, `UNIFIclientIp=` decoders
* Broadened lookahead patterns to prevent value bleed across KV fields
* Added `UNIFIutcTime` decoder for new timestamp field
* Added 10 new KV field decoders (clientMac, networkName, networkSubnet, networkVlan, deviceName, deviceModel, deviceIp, deviceMac, duration, ipsSessionId)
* Added hostapd device syslog decoders and rules (STA association, RADIUS auth)
* Added MITRE ATT&CK mappings to all rules
* Added 14 new CEF event rules: admin access (544), device adopted/offline (200/201), WiFi roaming (304), wired client connect/disconnect (302/303), honeypot (401+Security), firewall block CEF (402), WAN failover/latency/loss (500-502), PoE events (600-602)
* Added enrichment rule for IPS threats from internal hosts (100128)
* Added catch-all rule for unmatched CEF events (100199)
* Added 5 correlation/frequency rules for scan detection, attack detection, deauth, and RADIUS brute force
* Fixed event_id 401 collision between WiFi disconnect and honeypot using category disambiguation

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
