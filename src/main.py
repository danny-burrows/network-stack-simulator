import threading
from main_client import client
from main_server import server


def main() -> None:
    server_thread = threading.Thread(target=server)
    server_thread.start()
    client()
    server_thread.join()


if __name__ == "__main__":
    main()
