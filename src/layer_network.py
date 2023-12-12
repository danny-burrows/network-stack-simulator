from logger import Logger
from layer_physical import PhysicalLayer


class ResourceRecord:
    # https://tools.ietf.org/html/rfc1035#section-4.1.3
    # Prefixed all with rr_ to avoid name collisions
    rr_name: str
    rr_type: str
    rr_class: str
    rr_ttl: int
    rr_rdata: str

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        self.rr_name = rr_name
        self.rr_ttl = rr_ttl
        self.rr_rdata = rr_rdata

    @property
    def rr_rdlength(self) -> int:
        return len(self.rr_rdata)


class ARecord(ResourceRecord):
    rr_type: str = "A"
    rr_class: str = "IN"

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        super().__init__(rr_name, rr_ttl, rr_rdata)


class CNAMERecord(ResourceRecord):
    rr_type: str = "CNAME"
    rr_class: str = "IN"

    def __init__(self, rr_name: str, rr_ttl: int, rr_rdata: str):
        super().__init__(rr_name, rr_ttl, rr_rdata)


class DnsServer(Logger):
    records = set(
        (
            ARecord("gollum.mordor", 60, "192.168.1.6"),
            CNAMERecord("www.gollum.mordor", 60, "gollum.mordor"),
            CNAMERecord("rincewind.fourex.disc.atuin", 60, "gollum.mordor"),
        )
    )

    def __init__(self):
        super().__init__()

    def _find_record_from_name(self, name: str) -> ResourceRecord:
        for record in self.records:
            if record.rr_name == name:
                return record
        raise Exception(f"Record {name} not found")

    def resolve(self, host: str) -> str:
        self.logger.debug(f"Resolving host {host}...")
        while potential_record := self._find_record_from_name(host):
            if potential_record.rr_type == "A":
                return potential_record.rr_rdata
            elif potential_record.rr_type == "CNAME":
                host = potential_record.rr_rdata
        raise Exception(f"Could not resolve host {host}")


class NetworkLayer(Logger):
    @staticmethod
    def host_to_int(host: str) -> int:
        # Split the IP address into its four bytes and concatenate
        bytes = host.split(".")
        return (int(bytes[0]) << 24) + (int(bytes[1]) << 16) + (int(bytes[2]) << 8) + int(bytes[3])

    physical: PhysicalLayer
    src_host: str
    dest_host: str

    def __init__(self):
        super().__init__()
        self.physical = PhysicalLayer()

    def send(self, dest_host: str, data: bytes) -> None:
        self.logger.debug(f"⌛ Sending data=0x{data.hex()} from {NetworkLayer.src_host} to host {dest_host}...")
        self.logger.debug("⬇️  [Network->Physical]")
        self.physical.send(data)

    def receive(self, src_host: str) -> tuple[bytes, str]:
        data = self.physical.receive()
        self.logger.debug("⬆️  [Physical->Network]")
        self.logger.debug(f"✅ Received data=0x{data.hex()} to host {src_host} from {NetworkLayer.dest_host}")
        return data, NetworkLayer.dest_host
