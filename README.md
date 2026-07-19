# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                  |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------ | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py           |      381 |        7 |      132 |        6 |     97% |155-\>157, 182-\>189, 245-246, 277-285, 807-\>806, 832-\>834 |
| custom\_components/opnsense/binary\_sensor.py         |      196 |        1 |       86 |        0 |     99% |        51 |
| custom\_components/opnsense/config\_flow.py           |      445 |       14 |      184 |       22 |     94% |116, 172, 195-\>193, 246, 273, 279, 565-\>568, 625-\>637, 908, 1016-1020, 1098-\>1104, 1104-\>1107, 1128-\>1183, 1160-\>1183, 1161-\>1171, 1184, 1277-\>1280, 1351-\>1359, 1359-\>1362, 1398-1399, 1410 |
| custom\_components/opnsense/const.py                  |       75 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py            |      233 |        3 |      122 |        4 |     98% |106, 244-\>246, 449-\>452, 452-\>exit, 528-529, 535-\>538 |
| custom\_components/opnsense/device\_tracker.py        |      306 |        5 |      144 |        7 |     97% |161, 245, 300-\>302, 310, 385-\>368, 498, 570 |
| custom\_components/opnsense/entity.py                 |       95 |        0 |       24 |        2 |     98% |94-\>96, 180-\>182 |
| custom\_components/opnsense/helpers.py                |      159 |        5 |       78 |        5 |     96% |53, 130-\>121, 174, 178-179, 281, 285-\>273 |
| custom\_components/opnsense/migrate.py                |      245 |        5 |       98 |        5 |     97% |80, 318-\>321, 496-497, 509, 542 |
| custom\_components/opnsense/repair\_reconciliation.py |      141 |        0 |       48 |        2 |     99% |139-\>143, 177-\>179 |
| custom\_components/opnsense/repairs.py                |      230 |        3 |       88 |        6 |     97% |59-\>62, 269-\>271, 370-\>exit, 434-438, 503, 653-\>661 |
| custom\_components/opnsense/sensor.py                 |     1150 |       40 |      542 |       38 |     95% |484, 489, 493, 501-\>496, 526, 530, 536-539, 981, 984, 1048, 1123, 1188, 1208, 1228-1229, 1246, 1407, 1629, 1738, 1742, 1905, 1914-\>1917, 1924-\>1933, 1928-\>1933, 1930-\>1933, 1969-\>1971, 1971-\>1974, 2077, 2078-\>2085, 2209, 2254-2255, 2259-2260, 2263-2264, 2281-\>exit, 2332-2336, 2339-2340, 2348, 2378, 2598-\>2595, 2750-2752, 2776-\>2773 |
| custom\_components/opnsense/services.py               |      241 |        0 |       72 |        0 |    100% |           |
| custom\_components/opnsense/switch.py                 |      646 |       33 |      266 |       33 |     93% |41-\>44, 47-\>50, 75, 399, 455, 496, 768-769, 965-968, 1006, 1014, 1023, 1031, 1042, 1078, 1150-\>1158, 1170, 1178, 1187, 1195, 1206, 1241, 1248, 1249-\>1246, 1287, 1309, 1318, 1329, 1369, 1386, 1425-1429, 1456, 1473, 1558, 1614 |
| custom\_components/opnsense/traffic\_coordinator.py   |      174 |        0 |       62 |        4 |     98% |110-\>117, 172-\>169, 306-\>exit, 328-\>331 |
| custom\_components/opnsense/update.py                 |      183 |        2 |       56 |        2 |     98% |298-299, 302-\>304, 440-\>exit |
| **TOTAL**                                             | **4900** |  **118** | **2002** |  **136** | **96%** |           |


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