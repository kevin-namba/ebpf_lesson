from bcc import BPF
import sys
import time
b = BPF(src_file="redirect.c")

device = sys.argv[1]
# cloud_device = sys.argv[2]
b.attach_xdp(device, fn = b.load_func("xdp_redirect_func", BPF.XDP))
# b.attach_xdp(cloud_device, fn = b.load_func("xdp_dummy", BPF.XDP))
b.trace_print()
while True:
	try:
		time.sleep(1)
	except KeyboardInterrupt:
		break
b.remove_xdp(device)
