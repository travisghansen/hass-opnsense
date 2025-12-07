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
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1357 |      119 |      556 |      133 |     86% |37, 257->296, 330-331, 339->exit, 348->347, 350, 355-356, 389->414, 393->414, 397->414, 401->414, 412->414, 420-421, 449->507, 478, 487, 504->507, 533, 550->553, 610->613, 631-636, 660, 677, 682->691, 701-703, 710->714, 717->726, 719-720, 726->730, 743, 749, 754, 768, 771, 798, 800, 802, 804->796, 816, 818, 820, 822->814, 834, 836, 838, 840->832, 852, 854, 856, 858->850, 870, 872->868, 906, 908->907, 912, 964, 995-1001, 1011, 1013, 1018->1017, 1031, 1049, 1056-1058, 1071->1066, 1085-1086, 1090-1091, 1098, 1107, 1122, 1135-1137, 1150, 1160, 1179-1181, 1191, 1194, 1204, 1218-1223, 1242, 1249, 1256, 1258->1262, 1259->1258, 1263, 1276, 1285, 1305-1306, 1315-1316, 1338, 1343, 1376->1378, 1455, 1476, 1482->1495, 1497->1506, 1507->1522, 1510->1522, 1527, 1533, 1557, 1582, 1627, 1632->1625, 1646, 1647->exit, 1663, 1666->1661, 1676, 1699, 1720, 1755->1754, 1770, 1827->1826, 1835->1837, 1848, 1921, 1928, 1938-1939, 1958-1959, 1986-1987, 2115, 2131->2130, 2133->2128, 2156->2155, 2170->2169, 2172->2171, 2216->exit, 2237->2243, 2269->2268, 2300, 2324->2326, 2359, 2362, 2366, 2367->2364, 2376, 2379-2380, 2398, 2402, 2416->2422, 2422->2431, 2434-2435 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      497 |       43 |      204 |       39 |     88% |42->76, 44->76, 91->114, 99, 129->155, 132, 137, 250, 254, 310-319, 370->exit, 379-380, 415, 417->416, 419, 430-432, 446, 456, 468, 502, 510->509, 535, 541, 551, 557, 569, 600, 603->602, 605, 660, 667, 705, 718, 751-755, 758-760, 763-765, 785, 798, 882, 929 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
|                                              **TOTAL** | **3923** |  **277** | **1532** |  **284** | **89%** |           |


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