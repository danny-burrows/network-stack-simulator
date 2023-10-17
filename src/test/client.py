

import os
import time

path = "/var/tmp/testpipe"

if not os.path.exists(path):
    os.mkfifo(path)

print("Opening...")

with open(path, "w") as pipe_out:
    print("Open")
    pipe_out.write("Hello")

print("Test")
time.sleep(2)
while True:
    # time.sleep(0)
    with open(path, "w") as pipe_out:
        pipe_out.write("FRENCH")

print("Sent")

print("Closed")
