# ebpf_lesson
## prepare
install bcc
https://github.com/iovisor/bcc/blob/master/INSTALL.md

add submodule
```
git submodule update --init  
```

## set IP address
```
sudo ifconfig <dev_name> 192.168.11.1 netmask 255.255.255.0
```

## how to start
```
sudo -E python3 user.py <dev_name>
```

## how to start/stop
```
sudo ip link set dev <dev_name> xdp obj xdp_pass_kern.o sec xdp
sudo ip link set dev <dev_name> xdp off
```

## how to see docker eth
```
docker inspect --format '{{.State.Pid}}' <container-name>
sudo ln -s /proc/${pid}/ns/net /var/run/netns/<ns>

```

## atatch dammy program
```
sudo ip netns exec <ns> ip link set dev <dev_name> xdp obj xdp_pass_kern.o sec xdp
```
