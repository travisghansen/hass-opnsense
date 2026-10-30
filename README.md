# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                  |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------ | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py           |      411 |        7 |      144 |        5 |     97% |243-\>250, 326-327, 358-366, 943-\>942, 968-\>970 |
| custom\_components/opnsense/binary\_sensor.py         |      196 |        1 |       86 |        0 |     99% |        66 |
| custom\_components/opnsense/config\_flow.py           |      481 |       10 |      200 |       18 |     96% |165, 189-\>187, 240, 582-\>585, 645-\>657, 1127-1131, 1214-\>1220, 1220-\>1223, 1247-\>1302, 1279-\>1302, 1280-\>1290, 1303, 1399-\>1402, 1478-\>1486, 1486-\>1489, 1530-1531, 1550 |
| custom\_components/opnsense/const.py                  |       82 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py            |      312 |        2 |      164 |        4 |     99% |116-\>100, 398-\>400, 640-\>exit, 718-719, 725-\>728 |
| custom\_components/opnsense/device\_tracker.py        |      530 |        2 |      242 |        4 |     99% |414, 456-\>448, 672, 1141-\>1145 |
| custom\_components/opnsense/diagnostics.py            |      338 |        0 |      178 |        0 |    100% |           |
| custom\_components/opnsense/entity.py                 |       91 |        0 |       24 |        2 |     98% |97-\>99, 183-\>185 |
| custom\_components/opnsense/helpers.py                |      215 |        5 |      100 |        4 |     97% |223, 336-\>327, 380, 384-385, 479 |
| custom\_components/opnsense/migrate.py                |      249 |        2 |      100 |        3 |     99% |80, 322-\>325, 552 |
| custom\_components/opnsense/repair\_reconciliation.py |      141 |        0 |       48 |        2 |     99% |182-\>186, 224-\>226 |
| custom\_components/opnsense/repairs.py                |      235 |        3 |       88 |        6 |     97% |77-\>80, 307-\>309, 414-\>exit, 491-495, 563, 713-\>721 |
| custom\_components/opnsense/sensor.py                 |     1195 |       38 |      558 |       35 |     96% |615, 620, 624, 632-\>627, 657, 661, 667-670, 1151, 1215, 1292, 1361, 1381, 1401-1402, 1419, 1583, 1815, 1931, 2095, 2105-\>2114, 2109-\>2114, 2111-\>2114, 2189-\>2191, 2191-\>2194, 2297, 2298-\>2305, 2429, 2476-2477, 2481-2482, 2485-2486, 2503-\>exit, 2554-2558, 2561-2562, 2570, 2600, 2819-\>2816, 2975-2977, 3000-\>2997 |
| custom\_components/opnsense/services.py               |      249 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                 |      657 |       34 |      268 |       34 |     93% |55-\>58, 61-\>64, 132, 482, 538, 579, 845, 853-854, 1051-1054, 1092, 1100, 1109, 1117, 1128, 1164, 1236-\>1244, 1256, 1264, 1273, 1281, 1292, 1327, 1334, 1335-\>1332, 1373, 1395, 1404, 1415, 1455, 1472, 1511-1515, 1542, 1559, 1650, 1706 |
| custom\_components/opnsense/traffic\_coordinator.py   |      174 |        4 |       62 |        6 |     96% |111-\>118, 148, 173-\>170, 309-\>exit, 331-\>334, 335-341 |
| custom\_components/opnsense/update.py                 |      182 |        0 |       62 |        0 |    100% |           |
| **TOTAL**                                             | **5738** |  **108** | **2396** |  **123** | **97%** |           |


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