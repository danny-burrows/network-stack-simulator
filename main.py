import os
import time
import random
import threading


def simulation_init(simulation_pipe):
    if not os.path.exists(simulation_pipe):
        os.mkfifo(simulation_pipe)


def simulation_destroy(simulation_pipe):
    if os.path.exists(simulation_pipe):
        os.remove(simulation_pipe)


def client(simulation_pipe):    
    pipe_out = os.open(simulation_pipe, os.O_WRONLY)
    
    # Send some random messages
    for _ in range(3):
        random_message = f'Random Message: {random.random() * 1000:.0f}\n'
        os.write(pipe_out, random_message.encode())
        time.sleep(0.3)
    
    os.write(pipe_out, b'end\n')


def server(simulation_pipe):    
    with open(simulation_pipe, 'r') as pipe_in:
        while True:
            message = pipe_in.readline()[:-1]
            if message == 'end':
                print('Server: Recived "end" signal, shutting down.')
                break
            
            print(f'Server: Recived "{message}".')

    
def main():
    simulation_pipe = './client-pipe'  # Probably should be '/var/run/client-pipe'
    
    simulation_init(simulation_pipe)
    server_thread = threading.Thread(target=server, args=(simulation_pipe,))
    
    server_thread.start()
    client(simulation_pipe)
    server_thread.join()

    simulation_destroy(simulation_pipe)


if __name__ == "__main__":
    main()
