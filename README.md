# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                     |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|--------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py              |      420 |        8 |      148 |        5 |     97% |242-\>249, 325-326, 357-365, 942-\>941, 1054 |
| custom\_components/opnsense/binary\_sensor.py            |      196 |        1 |       86 |        0 |     99% |        66 |
| custom\_components/opnsense/config\_flow.py              |      456 |        5 |      188 |       15 |     97% |163, 187-\>185, 238, 580-\>583, 1073-\>1094, 1094-\>1096, 1177-\>1183, 1183-\>1186, 1240-\>1263, 1241-\>1251, 1358-\>1361, 1433-\>1441, 1441-\>1444, 1483-1484, 1503 |
| custom\_components/opnsense/const.py                     |       80 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py               |      300 |        2 |      146 |        2 |     99% |630-\>exit, 715-716, 722-\>725 |
| custom\_components/opnsense/device\_tracker.py           |      336 |        6 |      144 |        5 |     98% |107-108, 221, 253, 576, 578, 722-\>726 |
| custom\_components/opnsense/device\_tracker\_evidence.py |      188 |        1 |       72 |        3 |     98% |136, 538-\>536, 575-\>571 |
| custom\_components/opnsense/diagnostics.py               |      338 |        0 |      178 |        0 |    100% |           |
| custom\_components/opnsense/entity.py                    |       91 |        0 |       24 |        2 |     98% |97-\>99, 183-\>185 |
| custom\_components/opnsense/helpers.py                   |      216 |        3 |      102 |        4 |     98% |258, 341-\>332, 385, 484 |
| custom\_components/opnsense/migrate.py                   |      311 |        6 |      136 |        8 |     97% |88, 330-\>333, 565, 638-\>642, 647-\>650, 698, 711, 722-723 |
| custom\_components/opnsense/repair\_reconciliation.py    |      144 |        0 |       50 |        2 |     99% |182-\>186, 230-\>232 |
| custom\_components/opnsense/repairs.py                   |      235 |        3 |       88 |        6 |     97% |81-\>84, 311-\>313, 418-\>exit, 495-499, 565, 715-\>723 |
| custom\_components/opnsense/sensor.py                    |     1200 |       37 |      552 |       33 |     96% |623, 628, 632, 640-\>635, 665, 669, 675-678, 1159, 1292, 1361, 1381, 1401-1402, 1419, 1583, 1815, 1948, 2123, 2133-\>2142, 2137-\>2142, 2139-\>2142, 2217-\>2219, 2219-\>2222, 2325, 2326-\>2333, 2457, 2504-2505, 2509-2510, 2513-2514, 2531-\>exit, 2582-2586, 2589-2590, 2598, 2628, 3014-3016, 3039-\>3036 |
| custom\_components/opnsense/services.py                  |      249 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                    |      672 |       33 |      278 |       33 |     93% |56-\>59, 62-\>65, 133, 484, 540, 581, 865, 873-874, 1071-1074, 1112, 1120, 1129, 1137, 1148, 1184, 1256-\>1264, 1276, 1284, 1293, 1301, 1312, 1347, 1354, 1355-\>1352, 1393, 1415, 1424, 1435, 1475, 1492, 1531-1535, 1562, 1579, 1670 |
| custom\_components/opnsense/traffic\_coordinator.py      |      174 |        4 |       62 |        6 |     96% |111-\>118, 148, 173-\>170, 309-\>exit, 331-\>334, 335-341 |
| custom\_components/opnsense/update.py                    |      182 |        0 |       62 |        0 |    100% |           |
| **TOTAL**                                                | **5788** |  **109** | **2388** |  **124** | **97%** |           |


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