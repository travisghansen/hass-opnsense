# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                  |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------ | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py           |      381 |        7 |      132 |        6 |     97% |171-\>173, 209-\>216, 292-293, 324-332, 854-\>853, 879-\>881 |
| custom\_components/opnsense/binary\_sensor.py         |      196 |        1 |       86 |        0 |     99% |        66 |
| custom\_components/opnsense/config\_flow.py           |      445 |       14 |      184 |       22 |     94% |116, 174, 198-\>196, 249, 276, 282, 584-\>587, 647-\>659, 939, 1048-1052, 1131-\>1137, 1137-\>1140, 1162-\>1217, 1194-\>1217, 1195-\>1205, 1218, 1312-\>1315, 1387-\>1395, 1395-\>1398, 1437-1438, 1449 |
| custom\_components/opnsense/const.py                  |       76 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py            |      232 |        3 |      120 |        4 |     98% |107, 244-\>246, 449-\>452, 452-\>exit, 528-529, 535-\>538 |
| custom\_components/opnsense/device\_tracker.py        |      314 |        5 |      146 |        7 |     97% |165, 251, 306-\>308, 324, 405-\>386, 523, 595 |
| custom\_components/opnsense/diagnostics.py            |      338 |        0 |      178 |        0 |    100% |           |
| custom\_components/opnsense/entity.py                 |       95 |        0 |       24 |        2 |     98% |97-\>99, 183-\>185 |
| custom\_components/opnsense/helpers.py                |      198 |        6 |       92 |        6 |     96% |156, 269-\>260, 313, 317-318, 412, 423, 429-\>415 |
| custom\_components/opnsense/migrate.py                |      249 |        2 |      100 |        3 |     99% |80, 322-\>325, 552 |
| custom\_components/opnsense/repair\_reconciliation.py |      141 |        0 |       48 |        2 |     99% |182-\>186, 224-\>226 |
| custom\_components/opnsense/repairs.py                |      230 |        3 |       88 |        6 |     97% |73-\>76, 288-\>290, 395-\>exit, 472-476, 542, 692-\>700 |
| custom\_components/opnsense/sensor.py                 |     1194 |       38 |      560 |       36 |     96% |577, 582, 586, 594-\>589, 619, 623, 629-632, 1111, 1175, 1252, 1321, 1341, 1361-1362, 1379, 1543, 1775, 1890, 2057, 2066-\>2069, 2076-\>2085, 2080-\>2085, 2082-\>2085, 2160-\>2162, 2162-\>2165, 2268, 2269-\>2276, 2400, 2447-2448, 2452-2453, 2456-2457, 2474-\>exit, 2525-2529, 2532-2533, 2541, 2571, 2790-\>2787, 2942-2944, 2967-\>2964 |
| custom\_components/opnsense/services.py               |      241 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                 |      646 |       34 |      266 |       34 |     93% |55-\>58, 61-\>64, 119, 451, 507, 548, 812, 816-817, 1014-1017, 1055, 1063, 1072, 1080, 1091, 1127, 1199-\>1207, 1219, 1227, 1236, 1244, 1255, 1290, 1297, 1298-\>1295, 1336, 1358, 1367, 1378, 1418, 1435, 1474-1478, 1505, 1522, 1607, 1663 |
| custom\_components/opnsense/traffic\_coordinator.py   |      174 |        4 |       62 |        6 |     96% |111-\>118, 148, 173-\>170, 309-\>exit, 331-\>334, 335-341 |
| custom\_components/opnsense/update.py                 |      183 |        0 |       56 |        1 |     99% |442-\>exit |
| **TOTAL**                                             | **5333** |  **117** | **2214** |  **135** | **97%** |           |


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