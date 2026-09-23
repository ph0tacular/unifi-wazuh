# Rule File Load Order

How Wazuh orders rule files, why it matters for `unifi_rules.xml`, and how to verify your install after adding or renaming rule files.

## How `wazuh-analysisd` orders rule files

`wazuh-analysisd` loads *every* rule file - both the built-in ruleset in `ruleset/rules/` and everything you drop in `etc/rules/` - into **one combined list sorted alphabetically by filename**, ignoring which directory a file actually came from. This was confirmed by reading `src/config/rules-config.c`: the sort compares basenames only, so `<rule_dir>` order in `ossec.conf` has no effect on load order.

Every file in Wazuh's own stock ruleset is named `NNNN-description.xml` (`0010-rules_config.xml` ... `0999-malicious-ioc-rules.xml`). A custom file whose name *starts with a digit* can therefore sort ahead of a stock file it depends on and silently fail to attach. The symptom is `(7617)`/`(7619)`/`(7620)` "signature ID not found" warnings, which read as if the referenced rule doesn't exist when it actually just hasn't loaded yet.

## What this means for `unifi_rules.xml`

`unifi_rules.xml` is unaffected by that specific trap as shipped. Its rules chain from self-contained anchors (`100102`, `100200`, matched via `<decoded_as>`, not `<if_sid>1</if_sid>`), and because the filename starts with a letter, it naturally sorts after Wazuh's entire (digit-prefixed) stock ruleset.

Keep the following in mind if you customize:

- Don't rename this file to start with a digit (e.g. `0000_unifi_rules.xml`) unless you also make sure it still sorts after the stock ruleset. A `9999_`-style prefix keeps it last; a low prefix like `0000_` will not, and can break it.
- Any additional custom rule file that references these rule IDs via `<if_sid>` needs to sort *after* `unifi_rules.xml` in the same combined, directory-agnostic order.

## Verifying after you add or rename rule files

1. **Dry-run the parser** before restarting. This runs the real parser without touching the live daemon:

   ```bash
   sudo /var/ossec/bin/wazuh-analysisd -t
   ```

   Check the output for `(7611)`/`(7617)`/`(7619)`/`(7620)` warnings.

2. **Don't treat the warning count as a completeness check.** `ERRORLIST_MAXSIZE` (50, in `src/analysisd/logmsg.h`) silently evicts the *oldest* pending warning once a single file's failures exceed that count. A file with many broken rules can show only its last ~50 warnings, looking like a handful of isolated failures when most or all of that file's rules actually failed to attach.

3. **Don't rely on the API or dashboard to prove rules are attached.** The Wazuh API (`GET /rules?filename=...`) and the dashboard's Rules view list rule *definitions* from XML files; they don't prove `analysisd` attached those rules to its runtime tree.

4. **Replay representative events** with `wazuh-logtest` and confirm the expected final rule IDs match:

   ```bash
   sudo /var/ossec/bin/wazuh-logtest
   ```

5. **After a restart, confirm expected alerts are actually being produced** in normal operation.
