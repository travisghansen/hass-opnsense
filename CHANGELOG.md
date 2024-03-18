# v0.1.21

Released 2024-03-18

- increase timeout
- better logic for needs reboot on the firmware updater

# v0.1.20

Released 2024-02-17

- fix for disabled interfaces

# v0.1.19

Released 2024-02-17

- fix services (see #123)

# v0.1.18

Released 2024-02-15

- handle missing ipaddr property

# v0.1.17

Released 2024-02-11

- remove deprecated constants
- fix issue with interface stats in 24.1+

# v0.1.16

Released 2023-04-30

- minor fixes
- support for hass 2023.5

# v0.1.15

Released 2023-03-21

- temporary workaround for removal of `openvpn_get_active_servers()` in `23.1.4`

# v0.1.14

Released 2023-02-19

- update deprecated syntax (`exec_command()` replaced by `shell_safe()` in `23.1.1`)

# v0.1.13

Released 2023-01-30

- update deprecated syntax

# v0.1.12

Released 2023-01-29

- better unavailable logic

# v0.1.11

Released 2023-01-29

- proper data type

# v0.1.10

Released 2023-01-29

- update deprecated syntax
- minor updates/fixes
- better logging of api calls

# v0.1.9

Released 2023-01-22

- more robust handling of vip data structures

# v0.1.8

Released 2023-01-17

- more robust handling of vip data structures

# v0.1.7

Released 2023-01-16

- properly use `verify_ssl` data for REST client

# v0.1.6

Released 2023-01-16

- fix issue with update entity failing when opnsense date is not in UTC (#25 #54)

# v0.1.5

Released 2022-08-18

- refactor notice functionality due to breakage with 22.7.2

# v0.1.4

Released 2022-08-17

- remove notice functionality due to breakage with 22.7.2

# v0.1.3

Released 2022-08-17

- properly name the load average entities and remove unit of measure
- explicitly include `notices.inc` file

# v0.1.2

Released 2022-08-01

- better firmware update logic to support major `upgrades`

# v0.1.1

Released 2022-07-11

- ensure `state` data is reset each interval

# v0.1.0

Released 2022-07-09

- initial release
