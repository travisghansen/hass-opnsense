"""Custom exceptions for pyopnsense."""


class VoucherServerError(Exception):
    """Error from Voucher Server."""


class UnknownFirmware(Exception):
    """Unknown current firmware version."""
