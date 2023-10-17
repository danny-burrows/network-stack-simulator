
import os

path = "/var/tmp/testpipe"

if not os.path.exists(path):
    os.mkfifo(path)

print("Opening...")

with open(path, "r") as pipe_out:
    print("Open")
    while True:
        print("Reading")
        data = pipe_out.read()
        print(f"Received: {data=}")

print("Closed")
