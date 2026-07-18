# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                  |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------ | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py           |      368 |        7 |      124 |        5 |     97% |151-\>153, 178-\>185, 241-242, 273-281, 786-\>785 |
| custom\_components/opnsense/binary\_sensor.py         |      196 |        1 |       86 |        0 |     99% |        51 |
| custom\_components/opnsense/config\_flow.py           |      445 |       14 |      184 |       22 |     94% |116, 172, 195-\>193, 246, 273, 279, 565-\>568, 625-\>637, 908, 1016-1020, 1098-\>1104, 1104-\>1107, 1128-\>1183, 1160-\>1183, 1161-\>1171, 1184, 1277-\>1280, 1351-\>1359, 1359-\>1362, 1398-1399, 1410 |
| custom\_components/opnsense/const.py                  |       74 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py            |      233 |        3 |      122 |        4 |     98% |106, 244-\>246, 449-\>452, 452-\>exit, 528-529, 535-\>538 |
| custom\_components/opnsense/device\_tracker.py        |      306 |        5 |      144 |        7 |     97% |161, 245, 300-\>302, 310, 385-\>368, 498, 570 |
| custom\_components/opnsense/entity.py                 |       93 |        0 |       24 |        2 |     98% |91-\>93, 177-\>179 |
| custom\_components/opnsense/helpers.py                |      159 |        5 |       78 |        5 |     96% |53, 130-\>121, 174, 178-179, 281, 285-\>273 |
| custom\_components/opnsense/migrate.py                |      245 |        5 |       98 |        5 |     97% |80, 318-\>321, 496-497, 509, 542 |
| custom\_components/opnsense/repair\_reconciliation.py |      141 |        0 |       48 |        2 |     99% |139-\>143, 177-\>179 |
| custom\_components/opnsense/repairs.py                |      230 |        3 |       88 |        6 |     97% |59-\>62, 269-\>271, 370-\>exit, 434-438, 503, 653-\>661 |
| custom\_components/opnsense/sensor.py                 |     1101 |       34 |      530 |       34 |     96% |447, 452, 456, 464-\>459, 489, 493, 499-502, 943, 946, 1010, 1085, 1150, 1170, 1190-1191, 1208, 1369, 1573, 1682, 1686, 1849, 1858-\>1861, 1868-\>1877, 1872-\>1877, 1874-\>1877, 1913-\>1915, 1915-\>1918, 2021, 2022-\>2029, 2153, 2197-2201, 2204-2205, 2213, 2243, 2463-\>2460, 2615-2617, 2641-\>2638 |
| custom\_components/opnsense/services.py               |      241 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                 |      646 |       33 |      266 |       33 |     93% |41-\>44, 47-\>50, 75, 399, 455, 496, 768-769, 965-968, 1006, 1014, 1023, 1031, 1042, 1078, 1150-\>1158, 1170, 1178, 1187, 1195, 1206, 1241, 1248, 1249-\>1246, 1287, 1309, 1318, 1329, 1369, 1386, 1425-1429, 1456, 1473, 1558, 1614 |
| custom\_components/opnsense/update.py                 |      183 |        2 |       56 |        2 |     98% |298-299, 302-\>304, 440-\>exit |
| **TOTAL**                                             | **4661** |  **112** | **1920** |  **127** | **96%** |           |


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