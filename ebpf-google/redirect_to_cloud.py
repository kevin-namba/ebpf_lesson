from bcc import BPF
import pyroute2
import time
import sys
import ctypes as ct
flags = 0
def usage():
    print("Usage: {0} <in ifdev> <out ifdev>".format(sys.argv[0]))
    print("e.g.: {0} eth0 eth1\n".format(sys.argv[0]))
    exit(1)
if len(sys.argv) != 3:
    usage()
in_if = sys.argv[1]
out_if = sys.argv[2]
ip = pyroute2.IPRoute()
out_idx = ip.link_lookup(ifname=out_if)[0]
# load BPF program
b = BPF(src_file="redirect_to_cloud.c", cflags=["-w"])
tx_port = b.get_table("tx_port")
tx_port[0] = ct.c_int(out_idx)
in_fn = b.load_func("xdp_redirect_map", BPF.XDP)
out_fn = b.load_func("xdp_dummy", BPF.XDP)
b.attach_xdp(in_if, in_fn, flags)
b.attach_xdp(out_if, out_fn, flags)
rxcnt = b.get_table("rxcnt")
prev = 0
print("Printing redirected packets, hit CTRL+C to stop")
# b.trace_print()
while 1:
    try:
        val = rxcnt.sum(0).value
        if val:
            delta = val - prev
            prev = val
            print("{} pkt/s".format(delta))
        time.sleep(1)
    except KeyboardInterrupt:
        print("Removing filter from device")
        break
b.remove_xdp(in_if, flags)
b.remove_xdp(out_if, flags)