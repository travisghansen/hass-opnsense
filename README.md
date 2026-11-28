# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                     |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|--------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py              |      432 |        8 |      152 |        5 |     97% |280-\>287, 363-364, 395-403, 989-\>988, 1101 |
| custom\_components/opnsense/binary\_sensor.py            |      196 |        1 |       86 |        0 |     99% |        66 |
| custom\_components/opnsense/config\_flow.py              |      456 |        5 |      188 |       15 |     97% |163, 187-\>185, 238, 580-\>583, 1073-\>1094, 1094-\>1096, 1177-\>1183, 1183-\>1186, 1240-\>1263, 1241-\>1251, 1358-\>1361, 1433-\>1441, 1441-\>1444, 1483-1484, 1503 |
| custom\_components/opnsense/const.py                     |       82 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py               |      300 |        2 |      146 |        2 |     99% |630-\>exit, 715-716, 722-\>725 |
| custom\_components/opnsense/device\_tracker.py           |      336 |        6 |      144 |        5 |     98% |107-108, 221, 253, 576, 578, 722-\>726 |
| custom\_components/opnsense/device\_tracker\_evidence.py |      188 |        1 |       72 |        3 |     98% |136, 538-\>536, 575-\>571 |
| custom\_components/opnsense/diagnostics.py               |      350 |        0 |      186 |        0 |    100% |           |
| custom\_components/opnsense/entity.py                    |       92 |        0 |       24 |        2 |     98% |100-\>102, 186-\>188 |
| custom\_components/opnsense/helpers.py                   |      216 |        3 |      102 |        4 |     98% |258, 341-\>332, 385, 484 |
| custom\_components/opnsense/migrate.py                   |      311 |        6 |      136 |        8 |     97% |88, 330-\>333, 565, 638-\>642, 647-\>650, 698, 711, 722-723 |
| custom\_components/opnsense/query\_stats\_coordinator.py |       36 |        0 |        8 |        0 |    100% |           |
| custom\_components/opnsense/repair\_reconciliation.py    |      144 |        0 |       50 |        2 |     99% |182-\>186, 230-\>232 |
| custom\_components/opnsense/repairs.py                   |      235 |        3 |       88 |        6 |     97% |81-\>84, 311-\>313, 418-\>exit, 495-499, 565, 715-\>723 |
| custom\_components/opnsense/sensor.py                    |     1286 |       37 |      572 |       33 |     96% |635, 640, 644, 652-\>647, 677, 681, 687-690, 1171, 1304, 1373, 1393, 1413-1414, 1431, 1595, 1827, 1960, 2138, 2148-\>2157, 2152-\>2157, 2154-\>2157, 2232-\>2234, 2234-\>2237, 2340, 2341-\>2348, 2472, 2519-2520, 2524-2525, 2528-2529, 2546-\>exit, 2597-2601, 2604-2605, 2613, 2643, 3029-3031, 3054-\>3051 |
| custom\_components/opnsense/services.py                  |      267 |        0 |       74 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                    |      672 |       33 |      278 |       33 |     93% |56-\>59, 62-\>65, 133, 484, 540, 581, 865, 873-874, 1071-1074, 1112, 1120, 1129, 1137, 1148, 1184, 1256-\>1264, 1276, 1284, 1293, 1301, 1312, 1347, 1354, 1355-\>1352, 1393, 1415, 1424, 1435, 1475, 1492, 1531-1535, 1562, 1579, 1670 |
| custom\_components/opnsense/traffic\_coordinator.py      |      174 |        4 |       62 |        6 |     96% |111-\>118, 148, 173-\>170, 309-\>exit, 331-\>334, 335-341 |
| custom\_components/opnsense/update.py                    |      182 |        0 |       62 |        0 |    100% |           |
| **TOTAL**                                                | **5955** |  **109** | **2430** |  **124** | **97%** |           |


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