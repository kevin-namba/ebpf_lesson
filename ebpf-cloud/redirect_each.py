from bcc import BPF
import sys
import time
b = BPF(src_file="redirect_each.c")

container_device = sys.argv[1]
lan_device = sys.argv[2]
b.attach_xdp(container_device, fn = b.load_func("xdp_redirect_to_lan_func", BPF.XDP))
b.attach_xdp(lan_device, fn = b.load_func("xdp_redirect_to_container_func", BPF.XDP))
b.trace_print()
while True:
	try:
		time.sleep(1)
	except KeyboardInterrupt:
		break
b.remove_xdp(container_device)
b.remove_xdp(lan_device)