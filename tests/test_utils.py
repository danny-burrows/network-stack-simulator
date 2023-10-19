from src.utils import NetworkInterface


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

    client_recv_message = client_network_interface.receive()
    server_recv_message = server_network_interface.receive()

    assert client_recv_message == "Test server message"
    assert server_recv_message == "Test client message"

    server_network_interface.disconnect()
    client_network_interface.disconnect()
