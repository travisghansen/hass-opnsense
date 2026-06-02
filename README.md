# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      327 |       15 |      112 |       16 |     93% |90-\>86, 91-\>90, 178, 348, 351, 380-381, 391, 402-403, 486-\>485, 532-\>535, 736-\>734, 760-\>775, 767-\>760, 772, 776-778, 787-788, 809-810 |
| custom\_components/opnsense/binary\_sensor.py          |       84 |        0 |       24 |        0 |    100% |           |
| custom\_components/opnsense/client\_factory.py         |      228 |        7 |       74 |        4 |     96% |39-40, 44, 48-49, 152, 287-\>285, 537 |
| custom\_components/opnsense/client\_protocol.py        |       43 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/config\_flow.py            |      398 |       22 |      140 |       21 |     92% |89, 124, 129, 149-\>147, 182, 220, 226, 419, 427, 547-552, 569-574, 596, 721-\>723, 723-\>725, 725-\>728, 854, 914-918, 981-\>1003, 1003-\>1005, 1028, 1131, 1222-1223, 1225-\>1232 |
| custom\_components/opnsense/const.py                   |       75 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      188 |        4 |       86 |        8 |     96% |245-246, 311, 329-\>340, 354, 362-\>356, 385-\>388, 388-\>exit, 468-\>475 |
| custom\_components/opnsense/device\_tracker.py         |      210 |       19 |       82 |       14 |     89% |62, 78-\>77, 82-\>80, 84-85, 91-\>89, 98-99, 107, 125-\>123, 128-\>134, 168, 198, 212-\>211, 232-233, 251-\>265, 283-284, 287, 303-304, 332, 342-\>340, 344-345, 349, 350-\>exit |
| custom\_components/opnsense/entity.py                  |       57 |        0 |       12 |        2 |     97% |40-\>42, 84-\>86 |
| custom\_components/opnsense/helpers.py                 |       34 |        7 |       14 |        3 |     71% |17, 32, 53-57 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |        3 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_typing.py     |       41 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client.py       |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client\_base.py |      353 |       18 |       98 |       20 |     92% |97-\>100, 108, 143-\>149, 198-\>239, 277-284, 339-\>369, 343-\>369, 347-\>369, 351-\>369, 367-\>369, 412-\>472, 441, 452, 469-\>472, 515, 532-\>535, 657-\>660, 716, 751, 788-\>790, 796-797, 804-\>801, 806-807 |
| custom\_components/opnsense/pyopnsense/const.py        |        6 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/dhcp.py         |      210 |       52 |      100 |       33 |     69% |48-\>50, 65, 95-106, 119-120, 127, 129, 135, 136-\>133, 149, 167, 174-176, 194, 197, 204, 205-\>192, 225-228, 231-232, 237, 246, 261, 274-276, 294, 299, 300-\>303, 311, 329-330, 333-335, 355, 358, 359-\>362, 370, 384-392 |
| custom\_components/opnsense/pyopnsense/exceptions.py   |        3 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/firewall.py     |      264 |       55 |      138 |       27 |     74% |47, 49, 51, 53-\>45, 68, 70, 72, 74-\>66, 89, 91, 93, 95-\>87, 110, 112, 114, 116-\>108, 131, 133, 135-\>129, 312-336, 352-382, 419, 422, 426, 427-\>424, 436, 439-440, 458, 462 |
| custom\_components/opnsense/pyopnsense/firmware.py     |      118 |       16 |       38 |        9 |     84% |90-91, 125, 139-145, 158-\>160, 179, 184-\>193, 203-209, 217-218, 222-\>231, 224-225, 231-\>239, 274, 286 |
| custom\_components/opnsense/pyopnsense/helpers.py      |      112 |        6 |       42 |        2 |     95% |36, 180, 183-186 |
| custom\_components/opnsense/pyopnsense/services.py     |       54 |        4 |       16 |        2 |     91% |23, 31-32, 49 |
| custom\_components/opnsense/pyopnsense/speedtest.py    |       46 |        0 |       14 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/system.py       |      312 |       16 |      134 |       22 |     91% |38, 116-\>118, 118-\>120, 121, 126-\>111, 152, 155, 331-\>349, 338, 354-359, 377, 405, 428, 494, 530-\>521, 573, 582, 601, 655, 656-\>653, 664-\>666, 699, 702-\>701 |
| custom\_components/opnsense/pyopnsense/telemetry.py    |      187 |       11 |       52 |       15 |     89% |46, 51, 82-\>84, 170, 194, 202, 215-\>224, 225-\>238, 229, 243, 249, 278, 308, 325-\>324, 345 |
| custom\_components/opnsense/pyopnsense/unbound.py      |      104 |        8 |       38 |        9 |     88% |27, 41, 112, 119, 138-139, 143-\>165, 154-\>165, 198, 232 |
| custom\_components/opnsense/pyopnsense/vnstat.py       |      203 |       12 |       92 |       11 |     92% |187, 238, 303, 322-323, 333, 358, 360, 395, 427, 445, 466 |
| custom\_components/opnsense/pyopnsense/vouchers.py     |       40 |        2 |       16 |        4 |     89% |28, 37, 62-\>65, 66-\>70 |
| custom\_components/opnsense/pyopnsense/vpn.py          |      183 |        9 |       92 |       19 |     90% |76, 81-\>74, 100, 101-\>exit, 122, 125-\>120, 142, 145-\>147, 171, 197, 372, 393, 396-\>395, 398-\>391, 427-\>426, 441-\>440, 443-\>442, 498-\>exit, 535 |
| custom\_components/opnsense/sensor.py                  |      809 |       77 |      372 |       55 |     89% |67, 72, 76, 84-\>79, 109, 113, 119-122, 193, 196, 225, 255, 335, 377, 386-390, 394-395, 401, 419-420, 437, 474, 505, 604, 663, 701, 756, 768, 813, 858-\>860, 945, 952-954, 955-\>958, 966-\>976, 971-\>976, 973-\>976, 987-989, 993-995, 1000-1002, 1006-1008, 1016-\>1018, 1018-\>1021, 1079-1081, 1089-1091, 1095-1098, 1126-1128, 1129-\>1133, 1134-1136, 1176, 1201-1205, 1208-1209, 1217, 1254, 1283-1285, 1338-\>1337, 1351-\>1354, 1373, 1399-\>1396, 1520-\>1519, 1608-1610 |
| custom\_components/opnsense/services.py                |      204 |        1 |       90 |       12 |     96% |285-\>287, 295-\>297, 356-\>346, 391-\>381, 431-\>417, 447-\>434, 539-\>531, 575-\>563, 577-\>576, 622-\>607, 630, 734-\>726 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |112, 153, 158, 314, 318, 359, 402, 438, 443, 479, 484, 520, 525, 588, 611-616, 640-649, 716-\>exit, 727-728, 777, 784-787, 790-792, 795-798, 831, 839, 844, 852, 857-859, 917, 929-930, 934-936, 939-942, 986-\>994, 1010, 1018, 1023, 1031, 1036-1038, 1086, 1088-\>1087, 1090, 1102-1104, 1120, 1130, 1142, 1198, 1212-\>1211, 1242, 1248, 1258, 1264, 1276, 1329, 1332-\>1331, 1334, 1392, 1399, 1439, 1452, 1491-1495, 1498-1500, 1503-1505, 1527, 1540, 1631, 1686 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 161-162, 185-187, 188-\>198, 192-\>198, 194-\>193, 200-\>209, 216-217, 222 |
| **TOTAL**                                              | **5798** |  **464** | **2204** |  **374** | **89%** |           |


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