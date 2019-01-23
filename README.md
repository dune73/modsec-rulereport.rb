# modsec-rulereport.rb

New version of a script that extracts ModSec alert messages out of an apache error log and
proposes exclusion rules to make the supposed false positives disappear.

The script is meant to be used together with the ModSecurity / Core Rule Set
tuning methodology described at https://netnea.com. There is also a
ModSecurity tuning cheatsheet at netnea.com that illustrates the
various options of this script.

Multiple options exist to tailor the exclusion rule proposals.
These config snippets can then be included in the configuration
in order to tune a modsecurity installation,

```

Usage: STDIN | /home/dune73/bin/modsec-rulereport-new.rb [options]

Options:
    -d, --debug                      Display debugging infos
    -v, --verbose                    Be verbose
    -h, --help                       Displays Help
    -s, --startup                    Create startup time rule exclusion
    -r, --runtime                    Create runtime rule exclusion
    -R, --rule                       Create rule exclusion for a complete rule
    -T, --target                     Create rule exclusion for an individual target of a rule
    -i, --byid                       Select rule via rule id
    -t, --bytag                      Select rule via tag
    -m, --bymsg                      Select rule via message
```

# Notes

The order of the exclusion rules matter a lot within a ModSecurity
configuration. Startup time exxclusion rules need to be defined
after the rule triggering the false positives is being defined
(In case of the Core Rule Set, this means _after_ the CRS include).
Runtime rule exclusions on the other hand need to be configured
_before_ the CRS include.

There is a cheatsheet explaining the various options
(startup time / runtime, rule / target, by id / by tag, by message)
The cheatsheet can be downloaded from the netnea.com website. It
is linked from within the ModSecurity tutorials.
  
This script is (c) 2010-2019 by Christian Folini, netnea.com
It has been released under the GPLv3 license.
Contact: mailto:christian.folini@netnea.com
  
