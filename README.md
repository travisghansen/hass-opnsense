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
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |     1509 |      130 |      618 |      141 |     87% |52, 424->463, 560-561, 623->648, 627->648, 631->648, 635->648, 646->648, 655-656, 700->758, 729, 738, 755->758, 800, 817->820, 921->924, 1015-1020, 1072, 1097, 1102->1111, 1121-1127, 1134->1138, 1141->1150, 1143-1144, 1150->1154, 1180, 1194, 1212, 1234, 1237, 1278, 1280, 1282, 1284->1276, 1303, 1305, 1307, 1309->1301, 1328, 1330, 1332, 1334->1326, 1353, 1355, 1357, 1359->1351, 1378, 1380, 1382->1376, 1399, 1580, 1582, 1595, 1601, 1628-1631, 1633, 1635, 1648, 1654, 1719, 1721->1720, 1725, 1853, 1892-1898, 1916, 1918, 1923->1922, 1936, 1954, 1961-1963, 1990->1985, 2012-2013, 2017-2018, 2025, 2034, 2049, 2062-2064, 2088, 2098, 2117-2119, 2140, 2143, 2153, 2167-2172, 2207, 2214, 2221, 2223->2227, 2224->2223, 2228, 2249, 2258, 2308-2309, 2333-2334, 2372, 2377, 2410->2412, 2516, 2546, 2552->2565, 2567->2576, 2577->2592, 2580->2592, 2597, 2603, 2636, 2670, 2732, 2737->2730, 2760, 2761->exit, 2786, 2789->2784, 2808, 2840, 2870, 2920->2919, 2944, 3022->3021, 3030->3032, 3051, 3146, 3153, 3178-3179, 3195->3207, 3231-3232, 3272-3273, 3460, 3487->3486, 3489->3484, 3523->3522, 3537->3536, 3539->3538, 3604->exit, 3642->3648, 3695->3694, 3739, 3763->3765, 3826, 3829, 3833, 3834->3831, 3843, 3846-3847, 3865, 3869, 3883->3889, 3889->3898, 3901-3902 |
| custom\_components/opnsense/pyopnsense/const.py        |        4 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/sensor.py                  |      549 |       34 |      248 |       34 |     91% |86, 120, 148, 240, 288, 319, 367, 379, 424, 462->466, 466->468, 468->470, 470->472, 472->474, 474->476, 476->479, 549, 556-558, 559->562, 570->580, 575->580, 577->580, 591-593, 601-603, 607-610, 636-638, 639->643, 644-646, 681, 751->750, 764->767, 786, 810->807, 930->929, 1005-1007 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |127, 175, 180, 362, 366, 414, 464, 504, 509, 549, 554, 594, 599, 664, 687-692, 716-725, 802->exit, 812-813, 873, 880-883, 886-888, 891-894, 926, 934, 939, 947, 952-954, 1026, 1038-1039, 1043-1045, 1048-1051, 1095->1103, 1118, 1126, 1131, 1139, 1144-1146, 1204, 1206->1205, 1208, 1220-1222, 1236, 1246, 1258, 1327, 1341->1340, 1369, 1375, 1385, 1391, 1403, 1469, 1472->1471, 1474, 1530, 1537, 1575, 1588, 1632-1636, 1639-1641, 1644-1646, 1666, 1679, 1775, 1836 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **4313** |  **338** | **1680** |  **314** | **89%** |           |


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