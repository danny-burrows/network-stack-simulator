import struct

from layer_transport import TcpProtocol


def test_tcp_flags_to_string():
    tcp_flags = TcpProtocol.TcpFlags(syn=True, ack=True)
    tcp_flags_string = tcp_flags.to_string()

    assert tcp_flags_string == "010010"


def test_tcp_flags_to_bytes():
    tcp_flags = TcpProtocol.TcpFlags(syn=True, ack=True)
    tcp_flags_bytes = tcp_flags.to_bytes()

    assert tcp_flags_bytes == bytes([int("010010", base=2)])


def test_tcp_option_to_string():
    tcp_option = TcpProtocol.TcpOption(kind=0)
    tcp_option_string = tcp_option.to_string()

    assert tcp_option_string == "01"


def test_tcp_option_to_bytes():
    tcp_option = TcpProtocol.TcpOption(kind=0)
    tcp_option_bytes = tcp_option.to_bytes()

    assert tcp_option_bytes == bytes([0])


def test_tcp_option_to_bytes_with_data():
    tcp_option = TcpProtocol.TcpOption(kind=2, length=3, data=bytes([1]))
    tcp_option_bytes = tcp_option.to_bytes()

    assert tcp_option_bytes == bytes([2, 3, 1])


def test_tcp_packet_to_bytes():
    # Create a basic SYN packet
    tcp_flags = TcpProtocol.TcpFlags(syn=True)

    source_port = 59999
    destination_port = 80
    tcp_packet = TcpProtocol.create_packet(
        source_port,
        destination_port,
        flags=tcp_flags,
    )
    tcp_packet_bytes = tcp_packet.to_bytes()

    header_unpacked = struct.unpack("=HHIIBBHHH", tcp_packet_bytes[:20])

    assert header_unpacked == (
        59999,  # Source Port
        80,  # Destination Port
        0,  # Sequence Number
        0,  # Ack Number
        6 << 4,  # Data Offset (Right padded by 4)
        0b00000010,  # Flags (Left padded by 2)
        0,  # Window
        1,  # Checksum
        0,  # Urgent Pointer
    )
