import frrtest
import pytest
import os


if 'S["QUIC_TRUE"]=""\n' not in open("../config.status").readlines():
    class TestQuicSocket:
        @pytest.mark.skipif(True, reason="QUIC is not enabled")
        def test_exit_cleanly(self):
            pass
else:

    class TestQuicSocket(frrtest.TestMultiOut):
        program = "./test_quic_socket"

    TestQuicSocket.exit_cleanly()
