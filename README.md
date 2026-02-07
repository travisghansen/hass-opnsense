# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      280 |       12 |      102 |       16 |     93% |99->95, 100->99, 376, 387-388, 394->exit, 453->452, 514->518, 518->521, 648-649, 697->695, 721->736, 728->721, 733, 737-739, 748-749, 770-771 |
| custom\_components/opnsense/binary\_sensor.py          |       62 |        4 |        8 |        0 |     94% |   127-130 |
| custom\_components/opnsense/config\_flow.py            |      307 |       19 |      114 |       19 |     90% |185, 193, 273-274, 291-292, 312, 400->402, 402->404, 404->407, 482, 503, 541-545, 590->608, 608->610, 626, 677, 686, 739->747, 742, 750-751, 753->759, 764->767 |
| custom\_components/opnsense/const.py                   |       71 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      182 |        4 |       82 |        9 |     95% |208-209, 251->254, 263, 281->292, 301, 309->303, 332->335, 335->exit, 402->409 |
| custom\_components/opnsense/device\_tracker.py         |      207 |       18 |       80 |       13 |     89% |63, 79->78, 83->81, 85-86, 92->90, 99-100, 123->121, 126->132, 166, 196, 209->208, 229-230, 248->262, 280-281, 284, 300-301, 327, 337->335, 339-340, 344, 345->exit |
| custom\_components/opnsense/entity.py                  |       58 |        0 |       12 |        2 |     97% |34->36, 62->64 |
| custom\_components/opnsense/helpers.py                 |       26 |        2 |        8 |        2 |     88% |    17, 32 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1506 |      131 |      616 |      142 |     86% |37, 257->296, 352->351, 354, 359-360, 391->416, 395->416, 399->416, 403->416, 414->416, 422-423, 451->509, 480, 489, 506->509, 535, 552->555, 612->615, 679-684, 708, 725, 730->739, 749-755, 762->766, 769->778, 771-772, 778->782, 795, 801, 806, 820, 823, 850, 852, 854, 856->848, 868, 870, 872, 874->866, 886, 888, 890, 892->884, 904, 906, 908, 910->902, 922, 924, 926->920, 942, 1124, 1126, 1139, 1145, 1171-1174, 1176, 1178, 1191, 1197, 1228, 1230->1229, 1234, 1286, 1317-1323, 1333, 1335, 1340->1339, 1353, 1371, 1378-1380, 1393->1388, 1407-1408, 1412-1413, 1420, 1429, 1444, 1457-1459, 1482, 1492, 1511-1513, 1533, 1536, 1546, 1560-1565, 1584, 1591, 1598, 1600->1604, 1601->1600, 1605, 1618, 1627, 1647-1648, 1657-1658, 1680, 1685, 1718->1720, 1797, 1818, 1824->1837, 1839->1848, 1849->1864, 1852->1864, 1869, 1875, 1899, 1924, 1969, 1974->1967, 1988, 1989->exit, 2005, 2008->2003, 2018, 2041, 2062, 2097->2096, 2112, 2169->2168, 2177->2179, 2190, 2263, 2270, 2280-2281, 2300-2301, 2328-2329, 2457, 2473->2472, 2475->2470, 2498->2497, 2512->2511, 2514->2513, 2558->exit, 2579->2585, 2611->2610, 2642, 2666->2668, 2701, 2704, 2708, 2709->2706, 2718, 2721-2722, 2740, 2744, 2758->2764, 2764->2773, 2776-2777 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      698 |       89 |      280 |       63 |     84% |62->94, 128->151, 136, 186->212, 189, 194, 376, 380, 429, 432, 478, 519, 524, 565, 570, 611, 616, 681, 704-709, 733-742, 819->exit, 829-830, 890, 897-900, 903-905, 908-911, 943, 951, 956, 964, 969-971, 1043, 1055-1056, 1060-1062, 1065-1068, 1112->1120, 1135, 1143, 1148, 1156, 1161-1163, 1221, 1223->1222, 1225, 1237-1239, 1253, 1263, 1275, 1344, 1358->1357, 1386, 1392, 1402, 1408, 1420, 1486, 1489->1488, 1491, 1547, 1554, 1592, 1605, 1649-1653, 1656-1658, 1661-1663, 1683, 1696, 1792, 1853 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **4303** |  **340** | **1680** |  **319** | **89%** |           |


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