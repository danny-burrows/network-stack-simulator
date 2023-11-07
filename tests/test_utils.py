import os

from src.utils import NetworkInterface, NamedPipe


def test_named_pipe_only_creates_pipe_file_once(tmpdir):
    named_pipe_path = f"{tmpdir}/named-pipe"

    NamedPipe(named_pipe_path)
    creation_time = os.path.getctime(named_pipe_path)

    # Should be able to get a second handle to the file without recreation.
    NamedPipe(named_pipe_path)

    assert creation_time == os.path.getctime(named_pipe_path)


def test_named_pipe_only_deletes_pipe_file_once(tmpdir):
    named_pipe_handle = NamedPipe(f"{tmpdir}/named-pipe")

    named_pipe_handle.delete_pipe_file()
    named_pipe_handle.delete_pipe_file()


def test_network_interface_basic_connection(tmpdir):
    client_network_interface = NetworkInterface(
        send_pipe_path=f"{tmpdir}/server-eth0", recv_pipe_path=f"{tmpdir}/client-eth0"
    )
    server_network_interface = NetworkInterface(
        send_pipe_path=f"{tmpdir}/client-eth0", recv_pipe_path=f"{tmpdir}/server-eth0"
    )

    server_network_interface.connect()
    client_network_interface.connect()

    # Both these sends are necissary to unblock the named pipe "open" in the above "connect" methods
    client_network_interface.send("Test client message")
    server_network_interface.send("Test server message")

    server_network_interface.disconnect()
    client_network_interface.disconnect()


def test_network_interface_basic_recv(tmpdir):
    client_network_interface = NetworkInterface(
        send_pipe_path=f"{tmpdir}/server-eth0", recv_pipe_path=f"{tmpdir}/client-eth0"
    )
    server_network_interface = NetworkInterface(
        send_pipe_path=f"{tmpdir}/client-eth0", recv_pipe_path=f"{tmpdir}/server-eth0"
    )

    server_network_interface.connect()
    client_network_interface.connect()

    client_network_interface.send("Test client message")
    server_network_interface.send("Test server message")

    client_recv_message = client_network_interface.recv()
    server_recv_message = server_network_interface.recv()

    assert client_recv_message == "Test server message"
    assert server_recv_message == "Test client message"

    server_network_interface.disconnect()
    client_network_interface.disconnect()
