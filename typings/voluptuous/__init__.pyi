# Type-check ``voluptuous`` as probatio for every supported Home Assistant version.
# HA 2026.9+ aliases voluptuous to probatio at runtime, and HA 2026.10+ annotates
# flow schemas with probatio types. Pointing both our code and HA's own imports at
# probatio keeps mypy consistent from the minimum HA version through current.
# Delete this stub and import probatio directly once the minimum HA is 2026.10+.
from probatio import *
