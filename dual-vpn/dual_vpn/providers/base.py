import ipaddress
from dataclasses import dataclass, field


@dataclass
class ProviderStatus:
    name: str
    running: bool
    detail: str = ""
    interfaces: list = field(default_factory=list)
    endpoints: list = field(default_factory=list)


@dataclass
class Ctx:
    state_dir: object
    dry_run: bool = False


class VpnProvider:
    NAME = "base"

    def __init__(self, name, raw_config):
        self.name = name
        self.raw_config = raw_config

    def check(self, ctx):
        return []

    def validate(self):
        return None

    def start(self, ctx, bypasses):
        raise NotImplementedError

    def stop(self, ctx):
        raise NotImplementedError

    def status(self, ctx):
        return ProviderStatus(self.name, False, "не реализован")

    def endpoints(self, ctx):
        return []

    def interfaces(self, ctx):
        return []

    def owns_default_route(self):
        return False

    def probe(self, ctx):
        return None
