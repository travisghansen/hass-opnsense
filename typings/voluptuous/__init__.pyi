# Type-check ``voluptuous`` as probatio for every supported Home Assistant version.
# HA 2026.9+ aliases voluptuous to probatio at runtime, and HA 2026.10+ annotates
# flow schemas with probatio types. Pointing both our code and HA's own imports at
# probatio keeps mypy consistent from the minimum HA version through current.
#
# Limitation: mypy accepts probatio-only names and parameters that can fail at
# runtime. ``vol.Secret`` is missing from ``import voluptuous`` on every HA version,
# and ``vol.Schema(compile=...)`` raises TypeError below HA 2026.9. Below HA 2026.9,
# mypy also checks against probatio while HA runs real voluptuous. Tests on the
# supported HA versions must catch these.
#
# Delete this stub and import probatio directly once the minimum HA is 2026.10+.
from probatio import *
