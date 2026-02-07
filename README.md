# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      280 |       12 |      102 |       16 |     93% |99->95, 100->99, 376, 387-388, 394->exit, 453->452, 514->518, 518->521, 648-649, 697->695, 721->736, 728->721, 733, 737-739, 748-749, 770-771 |
| custom\_components/opnsense/binary\_sensor.py          |       62 |        4 |        8 |        0 |     94% |   127-130 |
| custom\_components/opnsense/config\_flow.py            |      307 |       19 |      114 |       19 |     90% |188, 196, 279-280, 297-298, 318, 406->408, 408->410, 410->413, 488, 509, 547-551, 600->622, 622->624, 640, 691, 700, 757->765, 760, 768-769, 771->777, 782->785 |
| custom\_components/opnsense/const.py                   |       71 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      185 |        4 |       84 |        9 |     95% |212-213, 255->258, 267, 285->296, 305, 313->307, 336->339, 339->exit, 406->413 |
| custom\_components/opnsense/device\_tracker.py         |      207 |       18 |       80 |       13 |     89% |63, 79->78, 83->81, 85-86, 92->90, 99-100, 123->121, 126->132, 166, 196, 209->208, 229-230, 248->262, 280-281, 284, 300-301, 327, 337->335, 339-340, 344, 345->exit |
| custom\_components/opnsense/entity.py                  |       58 |        0 |       12 |        2 |     97% |34->36, 62->64 |
| custom\_components/opnsense/helpers.py                 |       26 |        2 |        8 |        2 |     88% |    17, 32 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1505 |      130 |      618 |      140 |     87% |37, 257->296, 359-360, 391->416, 395->416, 399->416, 403->416, 414->416, 422-423, 451->509, 480, 489, 506->509, 535, 552->555, 612->615, 679-684, 715, 732, 737->746, 756-762, 769->773, 776->785, 778-779, 785->789, 802, 808, 813, 827, 830, 857, 859, 861, 863->855, 875, 877, 879, 881->873, 893, 895, 897, 899->891, 911, 913, 915, 917->909, 929, 931, 933->927, 949, 1131, 1133, 1146, 1152, 1178-1181, 1183, 1185, 1198, 1204, 1235, 1237->1236, 1241, 1293, 1324-1330, 1340, 1342, 1347->1346, 1360, 1378, 1385-1387, 1400->1395, 1414-1415, 1419-1420, 1427, 1436, 1451, 1464-1466, 1489, 1499, 1518-1520, 1540, 1543, 1553, 1567-1572, 1591, 1598, 1605, 1607->1611, 1608->1607, 1612, 1625, 1634, 1654-1655, 1664-1665, 1687, 1692, 1725->1727, 1804, 1825, 1831->1844, 1846->1855, 1856->1871, 1859->1871, 1876, 1882, 1906, 1931, 1976, 1981->1974, 1995, 1996->exit, 2012, 2015->2010, 2025, 2048, 2069, 2104->2103, 2119, 2176->2175, 2184->2186, 2197, 2270, 2277, 2287-2288, 2307-2308, 2335-2336, 2464, 2480->2479, 2482->2477, 2505->2504, 2519->2518, 2521->2520, 2565->exit, 2586->2592, 2618->2617, 2649, 2673->2675, 2708, 2711, 2715, 2716->2713, 2725, 2728-2729, 2747, 2751, 2765->2771, 2771->2780, 2783-2784 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      700 |       89 |      274 |       60 |     84% |127, 175, 180, 362, 366, 414, 417, 462, 502, 507, 547, 552, 592, 597, 662, 685-690, 714-723, 800->exit, 810-811, 871, 878-881, 884-886, 889-892, 924, 932, 937, 945, 950-952, 1024, 1036-1037, 1041-1043, 1046-1049, 1093->1101, 1116, 1124, 1129, 1137, 1142-1144, 1202, 1204->1203, 1206, 1218-1220, 1234, 1244, 1256, 1325, 1339->1338, 1367, 1373, 1383, 1389, 1401, 1467, 1470->1469, 1472, 1528, 1535, 1573, 1586, 1630-1634, 1637-1639, 1642-1644, 1664, 1677, 1773, 1834 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **4307** |  **339** | **1678** |  **314** | **89%** |           |


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