"""Tests for `pyopnsense.exceptions`."""

import pytest

from custom_components.opnsense import pyopnsense


def test_voucher_server_error() -> None:
    """Raise VoucherServerError to ensure the exception class exists."""
    with pytest.raises(pyopnsense.VoucherServerError):
        raise pyopnsense.VoucherServerError
