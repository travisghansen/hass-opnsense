# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      286 |       12 |      106 |       15 |     93% |99->95, 100->99, 383, 394-395, 482->481, 543->547, 547->550, 677-678, 726->724, 750->765, 757->750, 762, 766-768, 777-778, 799-800 |
| custom\_components/opnsense/binary\_sensor.py          |       62 |        4 |        8 |        0 |     94% |   127-130 |
| custom\_components/opnsense/config\_flow.py            |      386 |       23 |      140 |       22 |     91% |86, 132, 137, 162->160, 206, 254, 260, 418, 426, 509-510, 527-528, 548, 636->638, 638->640, 640->643, 781, 794, 832-836, 885->907, 907->909, 925, 1002, 1090-1091, 1093->1100 |
| custom\_components/opnsense/const.py                   |       75 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      189 |        4 |       88 |        9 |     95% |219-220, 262->265, 274, 292->303, 312, 320->314, 343->346, 346->exit, 412->419 |
| custom\_components/opnsense/device\_tracker.py         |      210 |       19 |       82 |       14 |     89% |63, 79->78, 83->81, 85-86, 92->90, 99-100, 108, 126->124, 129->135, 169, 199, 212->211, 232-233, 251->265, 283-284, 287, 303-304, 330, 340->338, 342-343, 347, 348->exit |
| custom\_components/opnsense/entity.py                  |       57 |        0 |       12 |        2 |     97% |33->35, 61->63 |
| custom\_components/opnsense/helpers.py                 |       26 |        2 |        8 |        2 |     88% |    17, 32 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |        3 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_typing.py     |       41 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client.py       |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client\_base.py |      351 |       18 |       98 |       20 |     92% |107->110, 118, 165->169, 227->267, 314-321, 387->417, 391->417, 395->417, 399->417, 415->417, 467->525, 496, 505, 522->525, 574, 591->594, 744->747, 822, 857, 892->894, 900-901, 908->905, 910-911 |
| custom\_components/opnsense/pyopnsense/const.py        |        5 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/dhcp.py         |      207 |       50 |       98 |       32 |     70% |58->60, 75, 109-120, 144, 146, 152, 153->150, 166, 184, 191-193, 217, 220, 227, 228->215, 253-254, 256-259, 264, 273, 288, 301-303, 327, 332, 333->336, 344, 362-363, 366-368, 394, 397, 398->401, 409, 423-431 |
| custom\_components/opnsense/pyopnsense/exceptions.py   |        2 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/firewall.py     |      264 |       55 |      138 |       27 |     74% |53, 55, 57, 59->51, 77, 79, 81, 83->75, 101, 103, 105, 107->99, 125, 127, 129, 131->123, 149, 151, 153->147, 360-384, 407-437, 485, 488, 492, 493->490, 502, 505-506, 524, 528 |
| custom\_components/opnsense/pyopnsense/firmware.py     |      118 |       14 |       38 |        9 |     85% |97-98, 140, 149-155, 171->173, 194, 199->208, 218-224, 231->234, 237->246, 239-240, 246->254, 293, 311 |
| custom\_components/opnsense/pyopnsense/helpers.py      |      100 |        6 |       34 |        2 |     94% |41, 212, 215-218 |
| custom\_components/opnsense/pyopnsense/services.py     |       54 |        4 |       16 |        2 |     91% |26, 34-35, 57 |
| custom\_components/opnsense/pyopnsense/speedtest.py    |       46 |        0 |       14 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/system.py       |      168 |       14 |       64 |       18 |     86% |63->81, 86-91, 113, 145, 172, 203, 210, 217, 219->223, 220->219, 224, 245, 254, 280, 345, 346->343, 354->356, 399, 402->401 |
| custom\_components/opnsense/pyopnsense/telemetry.py    |      187 |        9 |       52 |       15 |     90% |54, 59, 90->92, 190, 218, 225->236, 238->247, 248->261, 251->261, 266, 272, 305, 339, 360->359, 384 |
| custom\_components/opnsense/pyopnsense/unbound.py      |      104 |        8 |       38 |        9 |     88% |30, 44, 121, 128, 153-154, 158->179, 168->179, 216, 254 |
| custom\_components/opnsense/pyopnsense/vnstat.py       |      203 |       12 |       92 |       11 |     92% |201, 256, 340, 367-368, 378, 409, 411, 456, 499, 522, 549 |
| custom\_components/opnsense/pyopnsense/vouchers.py     |       40 |        2 |       16 |        4 |     89% |34, 43, 68->71, 72->76 |
| custom\_components/opnsense/pyopnsense/vpn.py          |      183 |        9 |       92 |       19 |     90% |89, 94->87, 117, 118->exit, 143, 146->141, 167, 170->172, 200, 230, 434, 460, 463->462, 465->458, 499->498, 513->512, 515->514, 580->exit, 625 |
| custom\_components/opnsense/sensor.py                  |      689 |       59 |      322 |       45 |     90% |72, 77, 81, 89->84, 120, 124, 130-133, 197, 200, 229, 258, 331, 365, 393, 485, 533, 564, 612, 624, 669, 713->715, 798, 805-807, 808->811, 819->829, 824->829, 826->829, 839-841, 845-847, 852-854, 858-860, 868->870, 870->873, 930-932, 940-942, 946-949, 975-977, 978->982, 983-985, 1020, 1090->1089, 1103->1106, 1125, 1149->1146, 1269->1268, 1344-1346 |
| custom\_components/opnsense/services.py                |      202 |        1 |       90 |       12 |     96% |278->280, 287->289, 330->320, 355->345, 384->371, 400->387, 460->452, 485->473, 487->486, 521->506, 529, 634->626 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |127, 175, 180, 362, 366, 414, 464, 504, 509, 549, 554, 594, 599, 665, 688-693, 717-726, 803->exit, 813-814, 874, 881-884, 887-889, 892-895, 927, 935, 940, 948, 953-955, 1027, 1039-1040, 1044-1046, 1049-1052, 1096->1104, 1119, 1127, 1132, 1140, 1145-1147, 1205, 1207->1206, 1209, 1221-1223, 1237, 1247, 1259, 1328, 1342->1341, 1370, 1376, 1386, 1392, 1404, 1470, 1473->1472, 1475, 1531, 1538, 1576, 1589, 1633-1637, 1640-1642, 1645-1647, 1667, 1680, 1776, 1835 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **5160** |  **428** | **1974** |  **355** | **88%** |           |


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