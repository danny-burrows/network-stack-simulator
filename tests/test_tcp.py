from layer_transport import TcpProtocol


def test_tcp_flags_to_string():
    tcp_flags = TcpProtocol.TcpFlags(syn=True, ack=True)
    tcp_flags_string = tcp_flags.to_string()

    assert tcp_flags_string == "Flags: 010010"


def test_tcp_flags_to_bytes():
    tcp_flags = TcpProtocol.TcpFlags(syn=True, ack=True)
    tcp_flags_bytes = tcp_flags.to_bytes()

    assert tcp_flags_bytes == bytes([int("010010", base=2)])


def test_tcp_option_to_string():
    tcp_option = TcpProtocol.TcpOption(kind=0)
    tcp_option_string = tcp_option.to_string()

    assert tcp_option_string == "Options: kind=0 length=1 data=b''"


def test_tcp_option_to_bytes():
    tcp_option = TcpProtocol.TcpOption(kind=0)
    tcp_option_bytes = tcp_option.to_bytes()

    assert tcp_option_bytes == bytes([0])


def test_tcp_option_to_bytes_with_data():
    tcp_option = TcpProtocol.TcpOption(kind=2, length=3, data=bytes([1]))
    tcp_option_bytes = tcp_option.to_bytes()

    assert tcp_option_bytes == bytes([2, 3, 1])
