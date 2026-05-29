"""Custom exceptions for pyopnsense."""


class OPNsenseVoucherServerError(Exception):
    """Error from Voucher Server."""


class OPNsenseUnknownFirmwareError(Exception):
    """Unknown current firmware version."""


OPNsenseUnknownFirmware = OPNsenseUnknownFirmwareError
