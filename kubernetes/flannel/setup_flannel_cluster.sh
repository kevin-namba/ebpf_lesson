sudo kubeadm reset
sudo rm -rf /etc/cni/net.d
sudo kubeadm init --pod-network-cidr=172.16.0.0/16
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl apply -f kube-flannel.yaml