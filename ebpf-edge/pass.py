from bcc import BPF
import sys
import time
b = BPF(src_file="pass.c")

device = sys.argv[1]
b.attach_xdp(device, fn = b.load_func("xdp_pass", BPF.XDP))
b.trace_print()
while True:
	try:
		time.sleep(1)
	except KeyboardInterrupt:
		break
b.remove_xdp(device)