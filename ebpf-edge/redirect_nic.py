from bcc import BPF
import sys
import time
b = BPF(src_file="redirect_nic.c")

nic_left = sys.argv[1]
nic_right = sys.argv[2]
b.attach_xdp(nic_left, fn = b.load_func("xdp_redirect_to_right", BPF.XDP))
b.attach_xdp(nic_right, fn = b.load_func("xdp_redirect_to_left", BPF.XDP))
b.trace_print()
while True:
	try:
		time.sleep(1)
	except KeyboardInterrupt:
		break
b.remove_xdp(nic_left)
b.remove_xdp(nic_right)