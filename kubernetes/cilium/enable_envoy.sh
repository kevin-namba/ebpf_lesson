helm upgrade cilium cilium/cilium --version 1.13.2 \
    --namespace kube-system \
    --reuse-values \
    --set-string extraConfig.enable-envoy-config=true
kubectl -n kube-system rollout restart deployment/cilium-operator
kubectl -n kube-system rollout restart ds/cilium
helm upgrade cilium cilium/cilium --version 1.13.2 \
    --namespace kube-system \
    --reuse-values \
    --set loadBalancer.l7.backend=envoy
kubectl -n kube-system rollout restart deployment/cilium-operator
kubectl -n kube-system rollout restart ds/cilium