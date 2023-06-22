sudo kubeadm reset
sudo rm -rf /etc/cni/net.d
sudo kubeadm init --skip-phases=addon/kube-proxy
mkdir -p $HOME/.kube
sudo cp -i /etc/kubernetes/admin.conf $HOME/.kube/config
sudo chown $(id -u):$(id -g) $HOME/.kube/config
helm repo add cilium https://helm.cilium.io/
helm install cilium cilium/cilium --version 1.13.2  \
    --namespace kube-system \
    --set kubeProxyReplacement=strict \
    --set k8sServiceHost=10.24.210.152 \
    --set k8sServicePort=6443
