from layer_transport import TcpProtocol

def test_tcp_flags_to_string():
    tcp_flags = TcpProtocol.TcpFlags(syn=True, ack=True)
    tcp_flags_string = tcp_flags.to_string()

    assert tcp_flags_string == "Flags: 010010"

def test_tcp_flags_to_bytes():
    tcp_flags = TcpProtocol.TcpFlags(syn=True, ack=True)
    tcp_flags_bytes = tcp_flags.to_bytes()

    assert tcp_flags_bytes == bytes([int("010010", base=2)])
