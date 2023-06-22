sudo kubeadm reset
sudo rm -rf /etc/cni/net.d
sudo kubeadm init --pod-network-cidr=192.168.2.0/24
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
kubectl create -f https://raw.githubusercontent.com/projectcalico/calico/v3.25.1/manifests/tigera-operator.yaml
kubectl apply -f custom-resources.yaml