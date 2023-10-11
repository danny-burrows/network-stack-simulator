
import os
import time
import random
import threading


def pipe_open(pipe_path):
    if not os.path.exists(pipe_path):
        os.mkfifo(pipe_path)


def pipe_close(pipe_path):
    if os.path.exists(pipe_path):
        os.remove(pipe_path)


def client(pipe_path):    
    pipe_out = os.open(pipe_path, os.O_WRONLY)
    
    # Send some random messages
    for _ in range(3):
        random_message = f'Random Message: {random.random() * 1000:.0f}\n'
        os.write(pipe_out, random_message.encode())
        time.sleep(0.3)
    
    os.write(pipe_out, b'end\n')


def server(pipe_path):    
    with open(pipe_path, 'r') as pipe_in:
        while True:
            message = pipe_in.readline()[:-1]
            if message == 'end':
                print('Server: Recived "end" signal, shutting down.')
                break
            
            print(f'Server: Recived "{message}".')

    
def main():
    pipe_path = '/tmp/client-pipe'
    
    pipe_open(pipe_path)
    server_thread = threading.Thread(target=server, args=(pipe_path,))
    server_thread.start()

    client(pipe_path)

    server_thread.join()
    pipe_close(pipe_path)


if __name__ == "__main__":
    main()
