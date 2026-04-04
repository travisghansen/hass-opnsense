"""Custom exceptions for pyopnsense."""


class OPNsenseVoucherServerError(Exception):
    """Error from Voucher Server."""


class OPNsenseUnknownFirmware(Exception):
    """Unknown current firmware version."""
