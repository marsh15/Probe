"""Stateful Docker boundary fake; labels and network endpoints behave like inspect."""

from types import SimpleNamespace

import docker


class Resource:
    def __init__(self, collection, name, labels, **kwargs):
        self.collection = collection
        self.name = name
        self.id = name
        self.kwargs = kwargs
        self.removed = False
        self.started = False
        self.attrs = {
            "Name": name,
            "Labels": labels,
            "Config": {"Labels": labels},
            "State": {"Running": False, "ExitCode": 0, "OOMKilled": False},
            "NetworkSettings": {"Networks": {}},
        }
        self.connections = {}
        self.stop_fails = False
        self.killed = False

    def reload(self):
        if self.removed:
            raise docker.errors.NotFound("removed")

    def remove(self, **kwargs):
        self.removed = True

    def connect(self, container, aliases=None):
        if self.collection.client.fail_connect:
            raise RuntimeError("connect failed")
        container.connections[self.name] = aliases or []

    def start(self):
        self.started = True
        self.attrs["State"]["Running"] = True

    def stop(self, timeout=5):
        if self.stop_fails:
            raise RuntimeError("stop failed")
        self.attrs["State"]["Running"] = False

    def kill(self):
        self.killed = True
        self.attrs["State"]["Running"] = False
        self.attrs["State"]["ExitCode"] = 137

    def logs(self, **kwargs):
        return b"container stderr"

    def wait(self, **kwargs):
        return {"StatusCode": 0}


class Collection:
    def __init__(self, client, kind):
        self.client = client
        self.kind = kind
        self.items = []

    def create(self, name=None, labels=None, **kwargs):
        resource = Resource(self, name, labels, **kwargs)
        if self.kind == "containers":
            resource.connections[kwargs.get("network")] = []
            for net, cfg in kwargs.get("networking_config", {}).items():
                if net == "EndpointsConfig":
                    continue  # high-level SDK rejects this already-encoded wrapper
                resource.connections[net] = cfg.get("Aliases", [])
        if self.kind == "networks":
            resource.attrs["IPAM"] = {"Config": [{"Subnet": "172.30.0.0/24"}]}
        self.items.append(resource)
        return resource

    def list(self, **kwargs):
        items = [r for r in self.items if not r.removed]
        label = kwargs.get("filters", {}).get("label")
        if label:
            key, _, value = label.partition("=")
            items = [
                r
                for r in items
                if key in r.attrs["Labels"] and (not value or r.attrs["Labels"][key] == value)
            ]
        return items

    def get(self, name):
        for resource in self.list():
            if resource.name == name:
                return resource
        raise docker.errors.NotFound("not found")


class Client:
    def __init__(self):
        self.fail_connect = False
        self.containers = Collection(self, "containers")
        self.networks = Collection(self, "networks")
        self.volumes = Collection(self, "volumes")
        self.images = SimpleNamespace(
            get=lambda image: SimpleNamespace(attrs={"Config": {}}, id=image)
        )
        self.api = SimpleNamespace(
            create_endpoint_config=lambda **kw: {"Aliases": kw.get("aliases", [])},
            create_networking_config=lambda cfg: {"EndpointsConfig": cfg},
        )

    def version(self):
        return {"Version": "26.1.0"}

    def ping(self):
        return True

    def info(self):
        return {"OSType": "linux", "Architecture": "aarch64", "Runtimes": {"runc": {}}}
