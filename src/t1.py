from kernel import Kernel
import threading
from protocols import TCPSocket

kernel = Kernel()
th = threading.Thread(target=kernel.run)
th.start()

sock = TCPSocket(kernel)
sock.connect("0.0.0.0", 3000)