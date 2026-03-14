# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      286 |       12 |      106 |       15 |     93% |99->95, 100->99, 383, 394-395, 482->481, 543->547, 547->550, 677-678, 726->724, 750->765, 757->750, 762, 766-768, 777-778, 799-800 |
| custom\_components/opnsense/binary\_sensor.py          |       62 |        4 |        8 |        0 |     94% |   127-130 |
| custom\_components/opnsense/config\_flow.py            |      305 |       19 |      112 |       19 |     90% |188, 196, 279-280, 297-298, 318, 406->408, 408->410, 410->413, 486, 507, 545-549, 598->620, 620->622, 638, 689, 698, 755->763, 758, 766-767, 769->775, 780->783 |
| custom\_components/opnsense/const.py                   |       72 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      187 |        4 |       86 |        9 |     95% |216-217, 259->262, 271, 289->300, 309, 317->311, 340->343, 343->exit, 409->416 |
| custom\_components/opnsense/device\_tracker.py         |      210 |       19 |       82 |       14 |     89% |63, 79->78, 83->81, 85-86, 92->90, 99-100, 108, 126->124, 129->135, 169, 199, 212->211, 232-233, 251->265, 283-284, 287, 303-304, 330, 340->338, 342-343, 347, 348->exit |
| custom\_components/opnsense/entity.py                  |       57 |        0 |       12 |        2 |     97% |33->35, 61->63 |
| custom\_components/opnsense/helpers.py                 |       26 |        2 |        8 |        2 |     88% |    17, 32 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |        3 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_typing.py     |       39 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client.py       |       12 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client\_base.py |      359 |       22 |       96 |       20 |     91% |97-98, 105-106, 128->131, 139, 186->190, 248->288, 335-342, 408->438, 412->438, 416->438, 420->438, 436->438, 488->546, 517, 526, 543->546, 588, 605->608, 707->710, 773, 822, 864->866, 872-873, 880->877, 882-883 |
| custom\_components/opnsense/pyopnsense/const.py        |       10 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/dhcp.py         |      207 |       50 |       98 |       32 |     70% |58->60, 75, 109-120, 144, 146, 152, 153->150, 166, 184, 191-193, 217, 220, 227, 228->215, 253-254, 256-259, 264, 273, 288, 301-303, 327, 332, 333->336, 344, 362-363, 366-368, 394, 397, 398->401, 409, 423-431 |
| custom\_components/opnsense/pyopnsense/exceptions.py   |        2 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/firewall.py     |      264 |       55 |      138 |       27 |     74% |53, 55, 57, 59->51, 77, 79, 81, 83->75, 101, 103, 105, 107->99, 125, 127, 129, 131->123, 149, 151, 153->147, 360-384, 407-437, 485, 488, 492, 493->490, 502, 505-506, 524, 528 |
| custom\_components/opnsense/pyopnsense/firmware.py     |      115 |       13 |       38 |        9 |     86% |81, 122, 131-137, 153->155, 176, 181->190, 200-206, 213->216, 219->228, 221-222, 228->236, 275, 293 |
| custom\_components/opnsense/pyopnsense/helpers.py      |      100 |       10 |       34 |        2 |     91% |41, 212, 215-218, 242-243, 266-267 |
| custom\_components/opnsense/pyopnsense/services.py     |       54 |        4 |       16 |        2 |     91% |26, 34-35, 57 |
| custom\_components/opnsense/pyopnsense/system.py       |      168 |       14 |       64 |       18 |     86% |63->81, 86-91, 113, 145, 172, 203, 210, 217, 219->223, 220->219, 224, 245, 254, 280, 345, 346->343, 354->356, 399, 402->401 |
| custom\_components/opnsense/pyopnsense/telemetry.py    |      187 |        9 |       52 |       15 |     90% |54, 59, 90->92, 190, 218, 225->236, 238->247, 248->261, 251->261, 266, 272, 305, 339, 360->359, 384 |
| custom\_components/opnsense/pyopnsense/unbound.py      |      104 |        8 |       38 |        9 |     88% |30, 44, 121, 128, 153-154, 158->179, 168->179, 216, 254 |
| custom\_components/opnsense/pyopnsense/vnstat.py       |      192 |       12 |       88 |       11 |     92% |170, 225, 309, 336-337, 347, 378, 380, 425, 468, 491, 518 |
| custom\_components/opnsense/pyopnsense/vouchers.py     |       40 |        2 |       16 |        4 |     89% |34, 43, 68->71, 72->76 |
| custom\_components/opnsense/pyopnsense/vpn.py          |      183 |        9 |       92 |       19 |     90% |89, 94->87, 117, 118->exit, 143, 146->141, 167, 170->172, 200, 230, 434, 460, 463->462, 465->458, 499->498, 513->512, 515->514, 580->exit, 625 |
| custom\_components/opnsense/sensor.py                  |      638 |       58 |      294 |       51 |     88% |71, 76, 80, 88->83, 119, 123, 129-132, 196, 199, 228, 256, 290, 318, 410, 458, 489, 537, 549, 594, 632->636, 636->638, 638->640, 640->642, 642->644, 644->646, 646->648, 648->651, 721, 728-730, 731->734, 742->752, 747->752, 749->752, 762-764, 768-770, 775-777, 781-783, 791->793, 793->796, 807-809, 817-819, 823-826, 852-854, 855->859, 860-862, 897, 967->966, 980->983, 1002, 1026->1023, 1146->1145, 1221-1223 |
| custom\_components/opnsense/services.py                |      166 |       12 |       78 |       12 |     90% |40-203, 248->250, 257->259, 300->290, 325->315, 354->341, 370->357, 430->422, 455->443, 457->456, 491->476, 499, 517->509 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |127, 175, 180, 362, 366, 414, 464, 504, 509, 549, 554, 594, 599, 665, 688-693, 717-726, 803->exit, 813-814, 874, 881-884, 887-889, 892-895, 927, 935, 940, 948, 953-955, 1027, 1039-1040, 1044-1046, 1049-1052, 1096->1104, 1119, 1127, 1132, 1140, 1145-1147, 1205, 1207->1206, 1209, 1221-1223, 1237, 1247, 1259, 1328, 1342->1341, 1370, 1376, 1386, 1392, 1404, 1470, 1473->1472, 1475, 1531, 1538, 1576, 1589, 1633-1637, 1640-1642, 1645-1647, 1667, 1680, 1776, 1835 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 154-155, 177-179, 180->190, 184->190, 186->185, 192->201, 207-208, 213 |
| **TOTAL**                                              | **4937** |  **441** | **1884** |  **358** | **88%** |           |


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