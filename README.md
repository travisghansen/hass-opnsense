# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                     |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|--------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py              |      420 |        8 |      148 |        5 |     97% |242-\>249, 325-326, 357-365, 942-\>941, 1054 |
| custom\_components/opnsense/binary\_sensor.py            |      196 |        1 |       86 |        0 |     99% |        66 |
| custom\_components/opnsense/config\_flow.py              |      456 |        5 |      188 |       15 |     97% |163, 187-\>185, 238, 580-\>583, 1073-\>1094, 1094-\>1096, 1177-\>1183, 1183-\>1186, 1240-\>1263, 1241-\>1251, 1358-\>1361, 1433-\>1441, 1441-\>1444, 1483-1484, 1503 |
| custom\_components/opnsense/const.py                     |       80 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py               |      300 |        2 |      146 |        2 |     99% |630-\>exit, 715-716, 722-\>725 |
| custom\_components/opnsense/device\_tracker.py           |      336 |        6 |      144 |        5 |     98% |107-108, 221, 253, 576, 578, 720-\>724 |
| custom\_components/opnsense/device\_tracker\_evidence.py |      188 |        1 |       72 |        3 |     98% |136, 538-\>536, 575-\>571 |
| custom\_components/opnsense/diagnostics.py               |      338 |        0 |      178 |        0 |    100% |           |
| custom\_components/opnsense/entity.py                    |       91 |        0 |       24 |        2 |     98% |97-\>99, 183-\>185 |
| custom\_components/opnsense/helpers.py                   |      216 |        3 |      102 |        4 |     98% |258, 341-\>332, 385, 484 |
| custom\_components/opnsense/migrate.py                   |      311 |        6 |      136 |        8 |     97% |88, 330-\>333, 560, 633-\>637, 642-\>645, 693, 706, 717-718 |
| custom\_components/opnsense/repair\_reconciliation.py    |      141 |        0 |       48 |        2 |     99% |182-\>186, 224-\>226 |
| custom\_components/opnsense/repairs.py                   |      235 |        3 |       88 |        6 |     97% |80-\>83, 310-\>312, 417-\>exit, 494-498, 564, 714-\>722 |
| custom\_components/opnsense/sensor.py                    |     1196 |       37 |      552 |       33 |     96% |621, 626, 630, 638-\>633, 663, 667, 673-676, 1157, 1290, 1359, 1379, 1399-1400, 1417, 1581, 1813, 1945, 2113, 2123-\>2132, 2127-\>2132, 2129-\>2132, 2207-\>2209, 2209-\>2212, 2315, 2316-\>2323, 2447, 2494-2495, 2499-2500, 2503-2504, 2521-\>exit, 2572-2576, 2579-2580, 2588, 2618, 3004-3006, 3029-\>3026 |
| custom\_components/opnsense/services.py                  |      249 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                    |      660 |       33 |      270 |       33 |     93% |55-\>58, 61-\>64, 132, 483, 539, 580, 846, 854-855, 1052-1055, 1093, 1101, 1110, 1118, 1129, 1165, 1237-\>1245, 1257, 1265, 1274, 1282, 1293, 1328, 1335, 1336-\>1333, 1374, 1396, 1405, 1416, 1456, 1473, 1512-1516, 1543, 1560, 1651 |
| custom\_components/opnsense/traffic\_coordinator.py      |      174 |        4 |       62 |        6 |     96% |111-\>118, 148, 173-\>170, 309-\>exit, 331-\>334, 335-341 |
| custom\_components/opnsense/update.py                    |      182 |        0 |       62 |        0 |    100% |           |
| **TOTAL**                                                | **5769** |  **109** | **2378** |  **124** | **97%** |           |


## Setup coverage badge

Below are examples of the badges you can use in your main branch `README` file.

### Direct image

[![Coverage badge](https://raw.githubusercontent.com/travisghansen/hass-opnsense/python-coverage-comment-action-data/badge.svg)](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

This is the one to use if your repository is private or if you don't want to customize anything.

### [Shields.io](https://shields.io) Json Endpoint

[![Coverage badge](https://img.shields.io/endpoint?url=https://raw.githubusercontent.com/travisghansen/hass-opnsense/python-coverage-comment-action-data/endpoint.json)](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

Using this one will allow you to [customize](https://shields.io/endpoint) the look of your badge.
It won't work with private repositories. It won't be refreshed more than once per five minutes.

### [Shields.io](https://shields.io) Dynamic Badge

[![Coverage badge](https://img.shields.io/badge/dynamic/json?color=brightgreen&label=coverage&query=%24.message&url=https%3A%2F%2Fraw.githubusercontent.com%2Ftravisghansen%2Fhass-opnsense%2Fpython-coverage-comment-action-data%2Fendpoint.json)](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

This one will always be the same color. It won't work for private repos. I'm not even sure why we included it.

## What is that?

This branch is part of the
[python-coverage-comment-action](https://github.com/marketplace/actions/python-coverage-comment)
GitHub Action. All the files in this branch are automatically generated and may be
overwritten at any moment.