sudo apt update
sudo apt install apt-transport-https ca-certificates curl gnupg-agent software-properties-common
curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -
sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"
sudo apt update
sudo apt install -y docker-ce docker-compose-plugin
sudo usermod -aG docker $USER
curl -s https://packages.cloud.google.com/apt/doc/apt-key.gpg | sudo apt-key add -
sudo apt-add-repository "deb http://apt.kubernetes.io/ kubernetes-xenial main"
sudo apt update
sudo apt install -y kubeadm kubelet kubectl
sudo swapoff -a
sudo cp -p /etc/fstab /etc/fstab_`date +%Y%m%d`
sudo vi /etc/fstab
## #/swapfile    none    swap    sw      0       0
sudo rm /swapfile
sudo mv /etc/containerd/config.toml /etc/containerd/config.toml_`date +%Y%m%d`
sudo systemctl restart containerd