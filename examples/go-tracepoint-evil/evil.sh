[astoycos@nfvsdn-02-oot examples]$ kubectl logs go-xdp-counter-ds-29klv -n go-xdp-counter
2023/10/31 03:04:06 Attached XDP program to iface "eth0" (index 2119)
2023/10/31 03:04:06 Press Ctrl-C to exit and remove the program
2023/10/31 03:04:09 25 packets received
2023/10/31 03:04:09 3809 bytes received

2023/10/31 03:04:12 49 packets received
2023/10/31 03:04:12 7552 bytes received

2023/10/31 03:04:15 49 packets received
2023/10/31 03:04:15 7552 bytes received


2023/10/30 13:49:24 
pid: 1284470

comm: coredns

token: ey{.....}oA

parsed token info: {
   "aud": [
      "https://kubernetes.default.svc.cluster.local"
   ],
   "exp": 1730208446,
   "iat": 1698672446,
   "iss": "https://kubernetes.default.svc.cluster.local",
   "kubernetes.io": {
      "namespace": "kube-system",
      "pod": {
         "name": "coredns-5d78c9869d-8fd5b",
         "uid": "ee7ee783-8d98-4ec9-8a2a-839863da835b"
      },
      "serviceaccount": {
         "name": "coredns",
         "uid": "2f730bae-fbe5-4d78-8090-721b080da198"
      },
      "warnafter": 1698676053
   },
   "nbf": 1698672446,
   "sub": "system:serviceaccount:kube-system:coredns"
}
