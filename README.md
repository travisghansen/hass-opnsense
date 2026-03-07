# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      286 |       12 |      106 |       15 |     93% |99->95, 100->99, 383, 394-395, 482->481, 543->547, 547->550, 677-678, 726->724, 750->765, 757->750, 762, 766-768, 777-778, 799-800 |
| custom\_components/opnsense/binary\_sensor.py          |       62 |        4 |        8 |        0 |     94% |   127-130 |
| custom\_components/opnsense/config\_flow.py            |      307 |       19 |      114 |       19 |     90% |188, 196, 279-280, 297-298, 318, 406->408, 408->410, 410->413, 488, 509, 547-551, 600->622, 622->624, 640, 691, 700, 757->765, 760, 768-769, 771->777, 782->785 |
| custom\_components/opnsense/const.py                   |       71 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      185 |        4 |       84 |        9 |     95% |213-214, 256->259, 268, 286->297, 306, 314->308, 337->340, 340->exit, 406->413 |
| custom\_components/opnsense/device\_tracker.py         |      207 |       18 |       80 |       13 |     89% |63, 79->78, 83->81, 85-86, 92->90, 99-100, 123->121, 126->132, 166, 196, 209->208, 229-230, 248->262, 280-281, 284, 300-301, 327, 337->335, 339-340, 344, 345->exit |
| custom\_components/opnsense/entity.py                  |       58 |        0 |       12 |        2 |     97% |34->36, 62->64 |
| custom\_components/opnsense/helpers.py                 |       26 |        2 |        8 |        2 |     88% |    17, 32 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1525 |      132 |      614 |      145 |     86% |52, 426->465, 554->556, 563, 585->587, 606-607, 669->694, 673->694, 677->694, 681->694, 692->694, 701-702, 746->804, 775, 784, 801->804, 846, 863->866, 967->970, 1061-1066, 1118, 1143, 1148->1157, 1167-1173, 1180->1184, 1187->1196, 1189-1190, 1196->1202, 1228, 1242, 1260, 1282, 1285, 1326, 1328, 1330, 1332->1324, 1351, 1353, 1355, 1357->1349, 1376, 1378, 1380, 1382->1374, 1401, 1403, 1405, 1407->1399, 1426, 1428, 1430->1424, 1625, 1627, 1640, 1646, 1673-1676, 1678, 1680, 1693, 1699, 1764, 1766->1765, 1770, 1898, 1937-1943, 1961, 1963, 1968->1967, 1981, 1999, 2006-2008, 2035->2030, 2054-2055, 2057-2058, 2065, 2074, 2089, 2102-2104, 2128, 2138, 2157-2159, 2180, 2183, 2193, 2207-2212, 2247, 2254, 2261, 2263->2267, 2264->2263, 2268, 2289, 2298, 2348-2349, 2373-2374, 2412, 2417, 2450->2452, 2556, 2586, 2592->2605, 2607->2616, 2617->2632, 2620->2632, 2637, 2643, 2676, 2710, 2772, 2777->2770, 2800, 2801->exit, 2826, 2829->2824, 2848, 2880, 2910, 2960->2959, 2984, 3062->3061, 3070->3072, 3091, 3183, 3190, 3215-3216, 3232->3244, 3265-3266, 3281, 3303-3304, 3319, 3491, 3518->3517, 3520->3515, 3554->3553, 3568->3567, 3570->3569, 3635->exit, 3673->3679, 3726->3725, 3770, 3794->3796, 3857, 3860, 3864, 3865->3862, 3874, 3877-3878, 3896, 3900, 3914->3920, 3920->3929, 3932-3933 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |127, 175, 180, 362, 366, 414, 464, 504, 509, 549, 554, 594, 599, 665, 688-693, 717-726, 803->exit, 813-814, 874, 881-884, 887-889, 892-895, 927, 935, 940, 948, 953-955, 1027, 1039-1040, 1044-1046, 1049-1052, 1096->1104, 1119, 1127, 1132, 1140, 1145-1147, 1205, 1207->1206, 1209, 1221-1223, 1237, 1247, 1259, 1328, 1342->1341, 1370, 1376, 1386, 1392, 1404, 1470, 1473->1472, 1475, 1531, 1538, 1576, 1589, 1633-1637, 1640-1642, 1645-1647, 1667, 1680, 1776, 1835 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **4335** |  **340** | **1680** |  **317** | **89%** |           |


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