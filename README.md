# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      253 |        9 |       90 |       14 |     93% |80->76, 81->80, 285->284, 311->315, 315->318, 426-427, 456->454, 480->495, 487->480, 492, 496-498, 507-508, 529-530 |
| custom\_components/opnsense/binary\_sensor.py          |       62 |        4 |        8 |        0 |     94% |   127-130 |
| custom\_components/opnsense/config\_flow.py            |      304 |       17 |      114 |       19 |     91% |185, 193, 273-274, 305, 393->395, 395->397, 397->400, 475, 496, 534-538, 583->601, 601->603, 619, 670, 679, 732->740, 735, 743-744, 746->752, 757->760 |
| custom\_components/opnsense/const.py                   |       71 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      182 |        4 |       82 |        9 |     95% |207-208, 250->253, 262, 280->291, 300, 308->302, 331->334, 334->exit, 401->408 |
| custom\_components/opnsense/device\_tracker.py         |      207 |       18 |       80 |       13 |     89% |63, 79->78, 83->81, 85-86, 92->90, 99-100, 123->121, 126->132, 166, 196, 209->208, 229-230, 248->262, 280-281, 284, 300-301, 327, 337->335, 339-340, 344, 345->exit |
| custom\_components/opnsense/entity.py                  |       58 |        0 |       12 |        2 |     97% |34->36, 62->64 |
| custom\_components/opnsense/helpers.py                 |       26 |        2 |        8 |        2 |     88% |    17, 32 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1380 |      119 |      566 |      133 |     86% |37, 257->296, 330-331, 339->exit, 348->347, 350, 355-356, 389->414, 393->414, 397->414, 401->414, 412->414, 420-421, 449->507, 478, 487, 504->507, 533, 550->553, 610->613, 677-682, 706, 723, 728->737, 747-749, 756->760, 763->772, 765-766, 772->776, 789, 795, 800, 814, 817, 844, 846, 848, 850->842, 862, 864, 866, 868->860, 880, 882, 884, 886->878, 898, 900, 902, 904->896, 916, 918->914, 952, 954->953, 958, 1010, 1041-1047, 1057, 1059, 1064->1063, 1077, 1095, 1102-1104, 1117->1112, 1131-1132, 1136-1137, 1144, 1153, 1168, 1181-1183, 1206, 1216, 1235-1237, 1257, 1260, 1270, 1284-1289, 1308, 1315, 1322, 1324->1328, 1325->1324, 1329, 1342, 1351, 1371-1372, 1381-1382, 1404, 1409, 1442->1444, 1521, 1542, 1548->1561, 1563->1572, 1573->1588, 1576->1588, 1593, 1599, 1623, 1648, 1693, 1698->1691, 1712, 1713->exit, 1729, 1732->1727, 1742, 1765, 1786, 1821->1820, 1836, 1893->1892, 1901->1903, 1914, 1987, 1994, 2004-2005, 2024-2025, 2052-2053, 2181, 2197->2196, 2199->2194, 2222->2221, 2236->2235, 2238->2237, 2282->exit, 2303->2309, 2335->2334, 2366, 2390->2392, 2425, 2428, 2432, 2433->2430, 2442, 2445-2446, 2464, 2468, 2482->2488, 2488->2497, 2500-2501 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      497 |       43 |      204 |       39 |     88% |42->76, 44->76, 91->114, 99, 129->155, 132, 137, 250, 254, 310-319, 370->exit, 379-380, 415, 417->416, 419, 430-432, 446, 456, 468, 502, 510->509, 535, 541, 551, 557, 569, 600, 603->602, 605, 660, 667, 705, 718, 751-755, 758-760, 763-765, 785, 798, 882, 929 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **3946** |  **277** | **1542** |  **284** | **89%** |           |


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