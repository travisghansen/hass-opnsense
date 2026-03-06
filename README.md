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
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1506 |      131 |      608 |      142 |     86% |52, 424->463, 561-562, 624->649, 628->649, 632->649, 636->649, 647->649, 656-657, 701->759, 730, 739, 756->759, 801, 818->821, 922->925, 1016-1021, 1073, 1098, 1103->1112, 1122-1128, 1135->1139, 1142->1151, 1144-1145, 1151->1155, 1181, 1195, 1213, 1235, 1238, 1279, 1281, 1283, 1285->1277, 1304, 1306, 1308, 1310->1302, 1329, 1331, 1333, 1335->1327, 1354, 1356, 1358, 1360->1352, 1379, 1381, 1383->1377, 1578, 1580, 1593, 1599, 1626-1629, 1631, 1633, 1646, 1652, 1717, 1719->1718, 1723, 1851, 1890-1896, 1914, 1916, 1921->1920, 1934, 1952, 1959-1961, 1988->1983, 2007-2008, 2010-2011, 2018, 2027, 2042, 2055-2057, 2081, 2091, 2110-2112, 2133, 2136, 2146, 2160-2165, 2200, 2207, 2214, 2216->2220, 2217->2216, 2221, 2242, 2251, 2301-2302, 2326-2327, 2365, 2370, 2403->2405, 2509, 2539, 2545->2558, 2560->2569, 2570->2585, 2573->2585, 2590, 2596, 2629, 2663, 2725, 2730->2723, 2753, 2754->exit, 2779, 2782->2777, 2801, 2833, 2863, 2913->2912, 2937, 3015->3014, 3023->3025, 3044, 3136, 3143, 3168-3169, 3185->3197, 3218-3219, 3234, 3256-3257, 3272, 3444, 3471->3470, 3473->3468, 3507->3506, 3521->3520, 3523->3522, 3588->exit, 3626->3632, 3679->3678, 3723, 3747->3749, 3810, 3813, 3817, 3818->3815, 3827, 3830-3831, 3849, 3853, 3867->3873, 3873->3882, 3885-3886 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |127, 175, 180, 362, 366, 414, 464, 504, 509, 549, 554, 594, 599, 664, 687-692, 716-725, 802->exit, 812-813, 873, 880-883, 886-888, 891-894, 926, 934, 939, 947, 952-954, 1026, 1038-1039, 1043-1045, 1048-1051, 1095->1103, 1118, 1126, 1131, 1139, 1144-1146, 1204, 1206->1205, 1208, 1220-1222, 1236, 1246, 1258, 1327, 1341->1340, 1369, 1375, 1385, 1391, 1403, 1469, 1472->1471, 1474, 1530, 1537, 1575, 1588, 1632-1636, 1639-1641, 1644-1646, 1666, 1679, 1775, 1836 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **4310** |  **339** | **1670** |  **315** | **89%** |           |


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