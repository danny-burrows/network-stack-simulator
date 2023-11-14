from layer_physical import PhysicalLayer
from layer_http import HttpLayer


def main() -> None:
    physical = PhysicalLayer()
    http = HttpLayer(physical)

    http.execute_client()


if __name__ == "__main__":
    main()
