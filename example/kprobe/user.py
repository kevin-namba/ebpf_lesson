from bcc import BPF
from bcc.utils import printb

# load BPF program
b = BPF(src_file="kern.c")
b.attach_kprobe(event=b.get_syscall_fnname("clone"), fn_name="hello")
b.trace_print()