# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                           |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|----------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py    |      279 |        7 |      100 |        3 |     96% |115-116, 147-155, 559-\>558 |
| custom\_components/opnsense/binary\_sensor.py  |      175 |        0 |       78 |        0 |    100% |           |
| custom\_components/opnsense/config\_flow.py    |      445 |       14 |      184 |       22 |     94% |116, 172, 195-\>193, 246, 273, 279, 565-\>568, 625-\>637, 908, 1016-1020, 1098-\>1104, 1104-\>1107, 1128-\>1183, 1160-\>1183, 1161-\>1171, 1184, 1277-\>1280, 1351-\>1359, 1359-\>1362, 1398-1399, 1410 |
| custom\_components/opnsense/const.py           |       74 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py     |      222 |        3 |      116 |        4 |     98% |100, 238-\>240, 432-\>435, 435-\>exit, 511-512, 518-\>521 |
| custom\_components/opnsense/device\_tracker.py |      281 |        5 |      128 |        7 |     97% |218, 265, 271, 289-\>295, 342-\>325, 455, 527 |
| custom\_components/opnsense/entity.py          |       93 |        0 |       24 |        2 |     98% |91-\>93, 177-\>179 |
| custom\_components/opnsense/helpers.py         |      159 |        5 |       78 |        5 |     96% |53, 130-\>121, 174, 178-179, 281, 285-\>273 |
| custom\_components/opnsense/migrate.py         |      245 |        5 |       98 |        5 |     97% |80, 318-\>321, 496-497, 509, 542 |
| custom\_components/opnsense/sensor.py          |     1040 |       36 |      506 |       35 |     95% |372, 381, 389-\>384, 414, 418, 424-427, 868, 871, 900, 935, 1010, 1079, 1088-1092, 1096-1097, 1103, 1123-1124, 1141, 1302, 1506, 1596-\>1598, 1707, 1716-\>1719, 1726-\>1735, 1730-\>1735, 1732-\>1735, 1771-\>1773, 1773-\>1776, 1879, 1880-\>1887, 2011, 2055-2059, 2062-2063, 2071, 2101, 2321-\>2318, 2473-2475, 2499-\>2496 |
| custom\_components/opnsense/services.py        |      241 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py          |      582 |       29 |      230 |       26 |     93% |392, 395, 436, 439, 646-647, 843-846, 884, 892, 901, 909, 920, 956, 1028-\>1036, 1048, 1056, 1065, 1073, 1084, 1192, 1203, 1243, 1260, 1299-1303, 1330, 1347, 1432, 1488 |
| custom\_components/opnsense/update.py          |      181 |        2 |       56 |        2 |     98% |296-297, 300-\>302, 438-\>exit |
| **TOTAL**                                      | **4017** |  **106** | **1670** |  **111** | **96%** |           |


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