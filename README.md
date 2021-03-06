# Kubeshift
[![Build Status](https://travis-ci.org/cdrage/kubeshift.svg?branch=master)](https://travis-ci.org/cdrage/kubeshift)
[![Coverage Status](https://coveralls.io/repos/github/cdrage/kubeshift/badge.svg?branch=master)](https://coveralls.io/github/cdrage/kubeshift?branch=master)

## Introduction

_Kubeshift_ is a multi-provider Python library for Kubernetes (kube) and Openshift (shift). We connect and communicate with each container orchestator 100% through their TLS (if available) HTTP API.

__Features:__

  - 100% HTTP API
  - Auto-parsing of `~/.kube/config`
  - `.kube/config` generation
  - TLS authentication
  - 100% test coverage with functional and integration tests

## Library installation

#### Pip
```bash
sudo pip install kubeshift
```

#### Manual / development
```bash
git clone https://github.com/cdrage/kubeshift && cd kubeshift
make install
```

#### Python requirements

```bash
▶ cat requirements.txt
PyYAML
requests
```

Public APIs
-----------
* [Config](config.md)
* [Query](query.md)
* [KubernetesClient](kube.md)
* [OpenshiftClient](shift.md)

#### Configuration import

The configuration file used with the provider must be an _object_. Currently we support the import and generation of Kubernetes and OpenShift configuration files .

```python
import kubeshift

# Import the configuration, this can be either from a file
config = kubeshift.Config.from_file("/home/user/.kube/config")

# Or generated via a set of parameters
config_params = kubeshift.Config.from_params(context_name="default", username="default", api="https://localhost:8080", auth="foobar", ca="/home/user/.kube/ca.cert", verify=True, filepath=None)

# Client connection
k8s_client = kubeshift.KubernetesClient(config)
oc_client = kubeshift.OpenshiftClient(config)
```

#### Named Query methods

API calls are also available via their corresponding method. Each call returns a `Query` object used to retrieve and filter.

**Methods Sourced through discovery**

- `http://localhost:8080/apis`
- `http://localhost:8080/oapi`


**Full example:**
```python
import kubeshift
import getpass

# Example k8s object
k8s_object = {"apiVersion": "v1", "kind": "Pod", "metadata": {"labels": {"app": "hellonginx"}, "name": "hellonginx"}, "spec": {
    "containers": [{"image": "nginx", "name": "hellonginx", "ports": [{"containerPort": 80, "hostPort": 80, "protocol": "TCP"}]}]}}

# Client configuration
user = getpass.getuser()
config = kubeshift.Config.from_file("/home/%s/.kube/config" % user)
client = kubeshift.KubernetesClient(config)

# Main methods
client.create(k8s_object)  # Creates the k8s object
# client.scale(k8s_object, replicas=3) # Scales the k8s object (if it's a service)
client.delete(k8s_object)  # Deletes the k8s object

# API calls

# Namespaces
client.namespaces().all()

# Pods
client.pods().all()
client.pods().filter(namespace="default", status="Running")
client.pods().metadata()
client.pods().items()
```

