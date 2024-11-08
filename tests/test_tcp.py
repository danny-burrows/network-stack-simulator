from layer_transport import TCPProtocol, TCPFlags, TCPOption

import struct


def test():
    pass


def test_tcp_flags_to_string():
    tcp_flags = TCPFlags(syn=True, ack=True)
    tcp_flags_string = tcp_flags.to_string()

    assert tcp_flags_string == "010010"


def test_tcp_flags_to_bytes():
    tcp_flags = TCPFlags(syn=True, ack=True)
    tcp_flags_bytes = tcp_flags.to_bytes()

    assert tcp_flags_bytes == bytes([int("010010", base=2)])


def test_tcp_parse_flags():
    tcp_flags_bytes = bytes([0b00010010])
    tcp_flags = TCPFlags.from_bytes(tcp_flags_bytes)

    assert tcp_flags == TCPFlags(syn=True, ack=True)


def test_tcp_option_to_string():
    tcp_option = TCPOption(kind=TCPOption.Kind.END_OF_OPTION_LIST)
    tcp_option_string = tcp_option.to_string()

    assert tcp_option_string == "kind=END_OF_OPTION_LIST"


def test_tcp_option_to_bytes():
    tcp_option = TCPOption(kind=TCPOption.Kind.END_OF_OPTION_LIST)
    tcp_option_bytes = tcp_option.to_bytes()

    assert tcp_option_bytes == bytes([0])


def test_tcp_option_to_bytes_with_data():
    tcp_option = TCPOption(kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE, data=bytes([1]))
    tcp_option_bytes = tcp_option.to_bytes()

    assert tcp_option_bytes == bytes([2, 3, 1])


def test_tcp_parse_option_with_no_data():
    tcp_option_bytes = bytes([0])
    tcp_option = TCPOption.from_bytes(tcp_option_bytes)

    assert tcp_option == TCPOption(kind=TCPOption.Kind.END_OF_OPTION_LIST)


def test_tcp_parse_option_with_data():
    tcp_option_bytes = bytes([2, 4, 0, 255])
    tcp_option = TCPOption.from_bytes(tcp_option_bytes)

    assert tcp_option == TCPOption(kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE, data=bytes([0, 255]))


def test_tcp_segment_to_bytes():
    # Create a basic SYN segment
    tcp_flags = TCPFlags(syn=True)

    source_port = 59999
    destination_port = 80
    tcp_segment = TCPProtocol.create_tcp_segment(
        source_port,
        destination_port,
        seq_number=0,
        ack_number=0,
        window=0,
        flags=tcp_flags,
    )
    tcp_segment_bytes = tcp_segment.to_bytes()

    # Minimal header (without options)
    MINIMAL_HEADER_SIZE_BYTES = 20
    assert len(tcp_segment_bytes) == MINIMAL_HEADER_SIZE_BYTES

    # Read and unpack just the minimal header bytes (without options)
    header_unpacked = struct.unpack(">HHIIBBHHH", tcp_segment_bytes)

    assert header_unpacked == (
        59999,  # Source Port
        80,  # Destination Port
        0,  # Sequence Number
        0,  # Ack Number
        5 << 4,  # Data Offset (Right padded by 4)
        0b00000010,  # Flags (Left padded by 2)
        0,  # Window
        0,  # Checksum
        0,  # Urgent Pointer
    )


def test_tcp_segment_to_bytes_with_options():
    # Create a basic SYNACK segment with some options
    tcp_flags = TCPFlags(syn=True, ack=True)

    tcp_options = [
        # Maximum segment size option
        TCPOption(
            kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE,
            data=struct.pack(">H", 65535),
        ),
        TCPOption(kind=TCPOption.Kind.NO_OPERATION),
        TCPOption(kind=TCPOption.Kind.NO_OPERATION),
        TCPOption(kind=TCPOption.Kind.END_OF_OPTION_LIST),
    ]

    source_port = 59999
    destination_port = 80
    tcp_segment = TCPProtocol.create_tcp_segment(
        source_port,
        destination_port,
        seq_number=0,
        ack_number=0,
        window=0,
        flags=tcp_flags,
        options=tcp_options,
    )
    tcp_segment_bytes = tcp_segment.to_bytes()

    # Minimal header (without options)
    MINIMAL_HEADER_SIZE_BYTES = 20

    # Options padded to be 2 full 4-byte (32-bit) words
    OPTIONS_SIZE_BYTES = 8

    # NB: No data included so size is:
    assert len(tcp_segment_bytes) == MINIMAL_HEADER_SIZE_BYTES + OPTIONS_SIZE_BYTES

    # Read and unpack just the minimal header bytes (without options)
    header_unpacked = struct.unpack(">HHIIBBHHH", tcp_segment_bytes[:20])
    assert header_unpacked == (
        59999,  # Source Port
        80,  # Destination Port
        0,  # Sequence Number
        0,  # Ack Number
        7 << 4,  # Data Offset (Right padded by 4)
        0b00010010,  # Flags (Left padded by 2)
        0,  # Window
        0,  # Checksum
        0,  # Urgent Pointer
    )

    options_unpacked = struct.unpack(">8B", tcp_segment_bytes[20:])
    assert options_unpacked == (
        # Max segment size
        2,
        4,
        255,
        255,
        # Two No-Op Options
        1,
        1,
        # End-of-options
        0,
        # Padding at the end to fill 2-byte words
        0,
    )


def test_tcp_parse_segment():
    # Create a basic SYN segment
    tcp_flags = TCPFlags(syn=True)

    source_port = 59999
    destination_port = 80
    tcp_segment = TCPProtocol.create_tcp_segment(
        source_port,
        destination_port,
        seq_number=0,
        ack_number=0,
        window=0,
        flags=tcp_flags,
    )
    tcp_segment_bytes = tcp_segment.to_bytes()

    assert TCPProtocol.parse_tcp_segment(tcp_segment_bytes) == tcp_segment


def test_tcp_parse_segment_with_options():
    # Create a basic SYNACK segment with some options
    tcp_flags = TCPFlags(syn=True, ack=True)

    tcp_options = [
        # Maximum segment size option
        TCPOption(
            kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE,
            data=struct.pack(">H", 65535),
        ),
        TCPOption(kind=TCPOption.Kind.NO_OPERATION),
        TCPOption(kind=TCPOption.Kind.NO_OPERATION),
        TCPOption(kind=TCPOption.Kind.END_OF_OPTION_LIST),
    ]

    source_port = 59999
    destination_port = 80
    tcp_segment = TCPProtocol.create_tcp_segment(
        source_port,
        destination_port,
        seq_number=0,
        ack_number=0,
        window=0,
        flags=tcp_flags,
        options=tcp_options,
    )
    tcp_segment_bytes = tcp_segment.to_bytes()

    assert TCPProtocol.parse_tcp_segment(tcp_segment_bytes) == tcp_segment


def test_tcp_parse_segment_with_options_and_data():
    # Create a basic SYNACK segment with some options
    tcp_flags = TCPFlags(syn=True, ack=True)

    tcp_options = [
        # Maximum segment size option
        TCPOption(
            kind=TCPOption.Kind.MAXIMUM_SEGMENT_SIZE,
            data=struct.pack(">H", 65535),
        ),
        TCPOption(kind=TCPOption.Kind.NO_OPERATION),
        TCPOption(kind=TCPOption.Kind.NO_OPERATION),
        TCPOption(kind=TCPOption.Kind.END_OF_OPTION_LIST),
    ]

    source_port = 59999
    destination_port = 80
    tcp_segment = TCPProtocol.create_tcp_segment(
        source_port,
        destination_port,
        seq_number=0,
        ack_number=0,
        window=0,
        flags=tcp_flags,
        options=tcp_options,
        data=bytes([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
    )
    tcp_segment_bytes = tcp_segment.to_bytes()

    assert TCPProtocol.parse_tcp_segment(tcp_segment_bytes) == tcp_segment
