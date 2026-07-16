# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                           |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|----------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py    |      231 |        7 |       88 |        3 |     96% |107-108, 140-148, 464-\>463 |
| custom\_components/opnsense/binary\_sensor.py  |      179 |        0 |       78 |        0 |    100% |           |
| custom\_components/opnsense/config\_flow.py    |      342 |       19 |      128 |       19 |     91% |94, 150, 173-\>171, 224, 262, 268, 545-\>557, 749, 807-811, 841-\>847, 847-\>850, 894-898, 919, 997, 1025-\>1033, 1033-\>1036, 1072-1073, 1086 |
| custom\_components/opnsense/const.py           |       70 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py     |      219 |        3 |      112 |        4 |     98% |100, 233-\>235, 421-\>424, 424-\>exit, 500-501, 507-\>510 |
| custom\_components/opnsense/device\_tracker.py |      284 |        5 |      130 |        7 |     97% |221, 268, 274, 292-\>298, 345-\>328, 458, 525 |
| custom\_components/opnsense/entity.py          |       93 |        0 |       24 |        2 |     98% |89-\>91, 175-\>177 |
| custom\_components/opnsense/helpers.py         |      111 |        5 |       54 |        5 |     94% |28, 80-\>71, 117, 121-122, 224, 228-\>216 |
| custom\_components/opnsense/migrate.py         |      245 |        5 |       98 |        5 |     97% |80, 318-\>321, 496-497, 509, 542 |
| custom\_components/opnsense/sensor.py          |      940 |       36 |      464 |       35 |     95% |354, 363, 371-\>366, 396, 400, 406-409, 825, 828, 857, 883, 971, 1036, 1045-1049, 1053-1054, 1060, 1080-1081, 1098, 1135, 1323, 1388-\>1390, 1475, 1484-\>1487, 1494-\>1503, 1498-\>1503, 1500-\>1503, 1539-\>1541, 1541-\>1544, 1650, 1651-\>1658, 1778, 1800-1804, 1807-1808, 1816, 1851, 2009-\>2006, 2157-2159, 2182-\>2179 |
| custom\_components/opnsense/services.py        |      230 |        0 |       64 |        0 |    100% |           |
| custom\_components/opnsense/switch.py          |      590 |       29 |      230 |       26 |     93% |392, 395, 436, 439, 646-647, 851-854, 892, 900, 909, 917, 928, 972, 1044-\>1052, 1064, 1072, 1081, 1089, 1100, 1224, 1235, 1275, 1292, 1331-1335, 1362, 1379, 1464, 1520 |
| custom\_components/opnsense/update.py          |      181 |        2 |       56 |        2 |     98% |296-297, 300-\>302, 438-\>exit |
| **TOTAL**                                      | **3715** |  **111** | **1526** |  **108** | **96%** |           |


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