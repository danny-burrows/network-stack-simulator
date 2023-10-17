import time
import threading

from main_client import client
from main_server import server

def main():
    server_thread = threading.Thread(target=server)
    server_thread.start()
    time.sleep(0.2)
    client()
    server_thread.join()


if __name__ == "__main__":
    main()
