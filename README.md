# Repository Coverage

[Full report](https://htmlpreview.github.io/?https://github.com/travisghansen/hass-opnsense/blob/python-coverage-comment-action-data/htmlcov/index.html)

| Name                                                   |    Stmts |     Miss |   Branch |   BrPart |   Cover |   Missing |
|------------------------------------------------------- | -------: | -------: | -------: | -------: | ------: | --------: |
| custom\_components/opnsense/\_\_init\_\_.py            |      328 |       15 |      114 |       17 |     93% |91-\>87, 92-\>91, 179, 348, 351, 380-381, 391, 402-403, 480-\>479, 523-\>527, 527-\>530, 731-\>729, 755-\>770, 762-\>755, 767, 771-773, 782-783, 804-805 |
| custom\_components/opnsense/binary\_sensor.py          |       43 |        4 |        4 |        0 |     91% |     92-95 |
| custom\_components/opnsense/client\_factory.py         |      190 |        6 |       62 |        3 |     96% |35-36, 40, 44-45, 210-\>208, 439 |
| custom\_components/opnsense/client\_protocol.py        |       43 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/config\_flow.py            |      394 |       22 |      140 |       21 |     92% |90, 125, 130, 150-\>148, 183, 221, 227, 417, 425, 545-550, 567-572, 594, 719-\>721, 721-\>723, 723-\>726, 851, 911-915, 978-\>1000, 1000-\>1002, 1025, 1128, 1218-1219, 1221-\>1228 |
| custom\_components/opnsense/const.py                   |       75 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/coordinator.py             |      189 |        4 |       88 |        9 |     95% |243-244, 295-\>298, 307, 325-\>336, 350, 358-\>352, 381-\>384, 384-\>exit, 465-\>472 |
| custom\_components/opnsense/device\_tracker.py         |      210 |       19 |       82 |       14 |     89% |63, 79-\>78, 83-\>81, 85-86, 92-\>90, 99-100, 108, 126-\>124, 129-\>135, 169, 199, 213-\>212, 233-234, 252-\>266, 284-285, 288, 304-305, 332, 342-\>340, 344-345, 349, 350-\>exit |
| custom\_components/opnsense/entity.py                  |       57 |        0 |       12 |        2 |     97% |40-\>42, 84-\>86 |
| custom\_components/opnsense/helpers.py                 |       34 |        7 |       14 |        3 |     71% |17, 32, 53-57 |
| custom\_components/opnsense/models.py                  |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_\_init\_\_.py |        3 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/\_typing.py     |       41 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client.py       |       13 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/client\_base.py |      351 |       18 |       98 |       20 |     92% |98-\>101, 109, 144-\>148, 196-\>236, 274-281, 334-\>364, 338-\>364, 342-\>364, 346-\>364, 362-\>364, 407-\>465, 436, 445, 462-\>465, 505, 522-\>525, 642-\>645, 699, 734, 769-\>771, 777-778, 785-\>782, 787-788 |
| custom\_components/opnsense/pyopnsense/const.py        |        5 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/dhcp.py         |      210 |       52 |      100 |       33 |     69% |46-\>48, 63, 93-104, 116-117, 124, 126, 132, 133-\>130, 146, 164, 171-173, 191, 194, 201, 202-\>189, 220-223, 226-227, 232, 241, 256, 269-271, 289, 294, 295-\>298, 306, 324-325, 328-330, 350, 353, 354-\>357, 365, 379-387 |
| custom\_components/opnsense/pyopnsense/exceptions.py   |        2 |        0 |        0 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/firewall.py     |      264 |       55 |      138 |       27 |     74% |47, 49, 51, 53-\>45, 68, 70, 72, 74-\>66, 89, 91, 93, 95-\>87, 110, 112, 114, 116-\>108, 131, 133, 135-\>129, 311-335, 350-380, 415, 418, 422, 423-\>420, 432, 435-436, 454, 458 |
| custom\_components/opnsense/pyopnsense/firmware.py     |      118 |       14 |       38 |        9 |     85% |90-91, 125, 139-145, 158-\>160, 177, 182-\>191, 201-207, 214-\>217, 220-\>229, 222-223, 229-\>237, 269, 281 |
| custom\_components/opnsense/pyopnsense/helpers.py      |      112 |        6 |       42 |        2 |     95% |36, 180, 183-186 |
| custom\_components/opnsense/pyopnsense/services.py     |       54 |        4 |       16 |        2 |     91% |23, 31-32, 49 |
| custom\_components/opnsense/pyopnsense/speedtest.py    |       46 |        0 |       14 |        0 |    100% |           |
| custom\_components/opnsense/pyopnsense/system.py       |      312 |       15 |      134 |       21 |     92% |38, 116-\>118, 118-\>120, 121, 126-\>111, 152, 155, 328-\>346, 351-356, 372, 400, 423, 489, 525-\>516, 568, 577, 596, 651, 652-\>649, 660-\>662, 695, 698-\>697 |
| custom\_components/opnsense/pyopnsense/telemetry.py    |      187 |        9 |       52 |       15 |     90% |46, 51, 82-\>84, 170, 194, 201-\>212, 214-\>223, 224-\>237, 227-\>237, 242, 248, 277, 307, 324-\>323, 344 |
| custom\_components/opnsense/pyopnsense/unbound.py      |      104 |        8 |       38 |        9 |     88% |27, 41, 110, 117, 136-137, 141-\>162, 151-\>162, 194, 227 |
| custom\_components/opnsense/pyopnsense/vnstat.py       |      203 |       12 |       92 |       11 |     92% |183, 233, 297, 316-317, 327, 351, 353, 388, 420, 438, 459 |
| custom\_components/opnsense/pyopnsense/vouchers.py     |       40 |        2 |       16 |        4 |     89% |28, 37, 62-\>65, 66-\>70 |
| custom\_components/opnsense/pyopnsense/vpn.py          |      183 |        9 |       92 |       19 |     90% |76, 81-\>74, 100, 101-\>exit, 122, 125-\>120, 142, 145-\>147, 171, 197, 370, 391, 394-\>393, 396-\>389, 425-\>424, 439-\>438, 441-\>440, 496-\>exit, 533 |
| custom\_components/opnsense/sensor.py                  |      791 |       77 |      364 |       55 |     88% |66, 71, 75, 83-\>78, 108, 112, 118-121, 192, 195, 224, 253, 333, 374, 383-387, 391-392, 398, 416-417, 434, 471, 502, 601, 656, 694, 749, 761, 806, 850-\>852, 937, 944-946, 947-\>950, 958-\>968, 963-\>968, 965-\>968, 979-981, 985-987, 992-994, 998-1000, 1008-\>1010, 1010-\>1013, 1071-1073, 1081-1083, 1087-1090, 1118-1120, 1121-\>1125, 1126-1128, 1163, 1188-1192, 1195-1196, 1204, 1241, 1270-1272, 1325-\>1324, 1338-\>1341, 1360, 1386-\>1383, 1507-\>1506, 1583-1585 |
| custom\_components/opnsense/services.py                |      202 |        1 |       90 |       12 |     96% |285-\>287, 294-\>296, 352-\>342, 386-\>376, 424-\>411, 440-\>427, 527-\>519, 561-\>549, 563-\>562, 606-\>591, 614, 715-\>707 |
| custom\_components/opnsense/switch.py                  |      702 |       88 |      276 |       59 |     85% |113, 154, 159, 313, 317, 358, 401, 434, 439, 472, 477, 510, 515, 576, 599-604, 628-637, 703-\>exit, 714-715, 764, 771-774, 777-779, 782-785, 817, 825, 830, 838, 843-845, 903, 915-916, 920-922, 925-928, 972-\>980, 995, 1003, 1008, 1016, 1021-1023, 1070, 1072-\>1071, 1074, 1086-1088, 1102, 1112, 1124, 1179, 1193-\>1192, 1221, 1227, 1237, 1243, 1255, 1307, 1310-\>1309, 1312, 1368, 1375, 1413, 1426, 1465-1469, 1472-1474, 1477-1479, 1499, 1512, 1603, 1656 |
| custom\_components/opnsense/update.py                  |      174 |       15 |       52 |        7 |     89% |30-48, 161-162, 185-187, 188-\>198, 192-\>198, 194-\>193, 200-\>209, 216-217, 222 |
| **TOTAL**                                              | **5693** |  **462** | **2168** |  **374** | **89%** |           |


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