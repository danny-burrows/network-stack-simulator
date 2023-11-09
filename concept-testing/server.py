import os
import time

path = "/var/tmp/testpipe"

if not os.path.exists(path):
    os.mkfifo(path)

print("Opening...")

# with os.fdopen(os.open(path, os.O_RDONLY | os.O_NONBLOCK)) as pipe_out:
with open(path, "r") as pipe_out:
    print("Open")
    while True:
        print("Reading")
        data = pipe_out.read()

        if data:
            print(f"Received: {data=}")

        time.sleep(0.01)

print("Closed")
