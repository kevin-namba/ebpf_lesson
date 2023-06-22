from bcc import BPF
from bcc.utils import printb
# u32で送られてくるのを`0.0.0.0`みたいな読みやすいものにする
def ntoa(addr):
    ipaddr = b''
    for n in range(0, 4):
        ipaddr = ipaddr + str(addr & 0xff).encode()
        if (n != 3):
            ipaddr = ipaddr + b'.'
        addr = addr >> 8
    return ipaddr

# 出力用の関数
def get_print_event(b: BPF):
    def print_event(cpu, data, size):
        event = b["events"].event(data)
        printb(b"%-6d %-16s %-16s %-16s %-16d" % (
            event.pid, event.comm, ntoa(event.saddr), ntoa(event.daddr), event.dport))

    return print_event


b = BPF(src_file="kern.c")
# プログラムのアタッチ
b.attach_kprobe(event='tcp_v4_connect', fn_name="tcp_connect")
b.attach_kretprobe(event='tcp_v4_connect', fn_name="tcp_connect_ret")


b["events"].open_perf_buffer(get_print_event(b))

print("%-6s %-16s %-16s %-16s %-16s" % (
        "PID","COMMAND", "S-IPADDR", "D-IPADDR", "DPORT"))
while 1:
   try:
      b.perf_buffer_poll()
   except KeyboardInterrupt:
      exit()
