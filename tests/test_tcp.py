import struct

from layer_transport import TcpProtocol, TcpOption, TcpFlags


def test():
    pass


# def test_tcp_flags_to_string():
#     tcp_flags = TcpFlags(syn=True, ack=True)
#     tcp_flags_string = tcp_flags.to_string()

#     assert tcp_flags_string == "010010"


# def test_tcp_flags_to_bytes():
#     tcp_flags = TcpFlags(syn=True, ack=True)
#     tcp_flags_bytes = tcp_flags.to_bytes()

#     assert tcp_flags_bytes == bytes([int("010010", base=2)])


# def test_tcp_parse_flags():
#     tcp_flags_bytes = bytes([0b00010010])
#     tcp_flags = TcpFlags.from_bytes(tcp_flags_bytes)

#     assert tcp_flags == TcpFlags(syn=True, ack=True)


# def test_tcp_option_to_string():
#     tcp_option = TcpOption(kind=TcpOption.Kind.END_OF_OPTION_LIST)
#     tcp_option_string = tcp_option.to_string()

#     assert tcp_option_string == "kind=0"


# def test_tcp_option_to_bytes():
#     tcp_option = TcpOption(kind=TcpOption.Kind.END_OF_OPTION_LIST)
#     tcp_option_bytes = tcp_option.to_bytes()

#     assert tcp_option_bytes == bytes([0])


# def test_tcp_option_to_bytes_with_data():
#     tcp_option = TcpOption(kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE, data=bytes([1]))
#     tcp_option_bytes = tcp_option.to_bytes()

#     assert tcp_option_bytes == bytes([2, 3, 1])


# def test_tcp_parse_option_with_no_data():
#     tcp_option_bytes = bytes([0])
#     tcp_option = TcpOption.from_bytes(tcp_option_bytes)

#     assert tcp_option == TcpOption(kind=TcpOption.Kind.END_OF_OPTION_LIST)


# def test_tcp_parse_option_with_data():
#     tcp_option_bytes = bytes([2, 4, 0, 255])
#     tcp_option = TcpOption.from_bytes(tcp_option_bytes)

#     assert tcp_option == TcpOption(kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE, data=bytes([0, 255]))


# def test_tcp_packet_to_bytes():
#     # Create a basic SYN packet
#     tcp_flags = TcpFlags(syn=True)

#     source_port = 59999
#     destination_port = 80
#     tcp_packet = TcpProtocol.create_packet(
#         source_port,
#         destination_port,
#         flags=tcp_flags,
#     )
#     tcp_packet_bytes = tcp_packet.to_bytes()

#     # Minimal header (without options)
#     MINIMAL_HEADER_SIZE_BYTES = 20
#     assert len(tcp_packet_bytes) == MINIMAL_HEADER_SIZE_BYTES

#     # Read and unpack just the minimal header bytes (without options)
#     header_unpacked = struct.unpack(">HHIIBBHHH", tcp_packet_bytes)

#     assert header_unpacked == (
#         59999,  # Source Port
#         80,  # Destination Port
#         0,  # Sequence Number
#         0,  # Ack Number
#         5 << 4,  # Data Offset (Right padded by 4)
#         0b00000010,  # Flags (Left padded by 2)
#         0,  # Window
#         0,  # Checksum
#         0,  # Urgent Pointer
#     )


# def test_tcp_packet_to_bytes_with_options():
#     # Create a basic SYNACK packet with some options
#     tcp_flags = TcpFlags(syn=True, ack=True)

#     tcp_options = [
#         # Maximum segment size option
#         TcpOption(
#             kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE,
#             data=struct.pack(">H", 65535),
#         ),
#         TcpOption(kind=TcpOption.Kind.NO_OPERATION),
#         TcpOption(kind=TcpOption.Kind.NO_OPERATION),
#         TcpOption(kind=TcpOption.Kind.END_OF_OPTION_LIST),
#     ]

#     source_port = 59999
#     destination_port = 80
#     tcp_packet = TcpProtocol.create_packet(
#         source_port,
#         destination_port,
#         flags=tcp_flags,
#         options=tcp_options,
#     )
#     tcp_packet_bytes = tcp_packet.to_bytes()

#     # Minimal header (without options)
#     MINIMAL_HEADER_SIZE_BYTES = 20

#     # Options padded to be 2 full 4-byte (32-bit) words
#     OPTIONS_SIZE_BYTES = 8

#     # NB: No data included so size is:
#     assert len(tcp_packet_bytes) == MINIMAL_HEADER_SIZE_BYTES + OPTIONS_SIZE_BYTES

#     # Read and unpack just the minimal header bytes (without options)
#     header_unpacked = struct.unpack(">HHIIBBHHH", tcp_packet_bytes[:20])
#     assert header_unpacked == (
#         59999,  # Source Port
#         80,  # Destination Port
#         0,  # Sequence Number
#         0,  # Ack Number
#         7 << 4,  # Data Offset (Right padded by 4)
#         0b00010010,  # Flags (Left padded by 2)
#         0,  # Window
#         0,  # Checksum
#         0,  # Urgent Pointer
#     )

#     options_unpacked = struct.unpack(">8B", tcp_packet_bytes[20:])
#     assert options_unpacked == (
#         # Max segment size
#         2,
#         4,
#         255,
#         255,
#         # Two No-Op Options
#         1,
#         1,
#         # End-of-options
#         0,
#         # Padding at the end to fill 2-byte words
#         0,
#     )


# def test_tcp_parse_packet():
#     # Create a basic SYN packet
#     tcp_flags = TcpFlags(syn=True)

#     source_port = 59999
#     destination_port = 80
#     tcp_packet = TcpProtocol.create_packet(
#         source_port,
#         destination_port,
#         flags=tcp_flags,
#     )
#     tcp_packet_bytes = tcp_packet.to_bytes()

#     assert TcpProtocol.parse_packet(tcp_packet_bytes) == tcp_packet


# def test_tcp_parse_packet_with_options():
#     # Create a basic SYNACK packet with some options
#     tcp_flags = TcpFlags(syn=True, ack=True)

#     tcp_options = [
#         # Maximum segment size option
#         TcpOption(
#             kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE,
#             data=struct.pack(">H", 65535),
#         ),
#         TcpOption(kind=TcpOption.Kind.NO_OPERATION),
#         TcpOption(kind=TcpOption.Kind.NO_OPERATION),
#         TcpOption(kind=TcpOption.Kind.END_OF_OPTION_LIST),
#     ]

#     source_port = 59999
#     destination_port = 80
#     tcp_packet = TcpProtocol.create_packet(
#         source_port,
#         destination_port,
#         flags=tcp_flags,
#         options=tcp_options,
#     )
#     tcp_packet_bytes = tcp_packet.to_bytes()

#     assert TcpProtocol.parse_packet(tcp_packet_bytes) == tcp_packet


# def test_tcp_parse_packet_with_options_and_data():
#     # Create a basic SYNACK packet with some options
#     tcp_flags = TcpFlags(syn=True, ack=True)

#     tcp_options = [
#         # Maximum segment size option
#         TcpOption(
#             kind=TcpOption.Kind.MAXIMUM_SEGMENT_SIZE,
#             data=struct.pack(">H", 65535),
#         ),
#         TcpOption(kind=TcpOption.Kind.NO_OPERATION),
#         TcpOption(kind=TcpOption.Kind.NO_OPERATION),
#         TcpOption(kind=TcpOption.Kind.END_OF_OPTION_LIST),
#     ]

#     source_port = 59999
#     destination_port = 80
#     tcp_packet = TcpProtocol.create_packet(
#         source_port,
#         destination_port,
#         flags=tcp_flags,
#         options=tcp_options,
#         data=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
#     )
#     tcp_packet_bytes = tcp_packet.to_bytes()

#     assert TcpProtocol.parse_packet(tcp_packet_bytes) == tcp_packet
