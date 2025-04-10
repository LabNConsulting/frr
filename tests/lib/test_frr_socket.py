import frrtest


class TestFrrSocket(frrtest.TestMultiOut):
    program = "./test_frr_socket"


TestFrrSocket.exit_cleanly()
