

import os
import time

path = "/var/tmp/testpipe"

if not os.path.exists(path):
    os.mkfifo(path)

print("Opening...")

with open(path, "w") as pipe_out:
    print("Open")
    pipe_out.write("Hello")
    time.sleep(10)
    pipe_out.write("Hello")
    time.sleep(10)
    pipe_out.write("Hello")
    print("Sent")

print("Closed")
