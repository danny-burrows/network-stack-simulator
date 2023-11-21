from layer_physical import PhysicalLayer
from layer_http import HttpLayer


def main() -> None:
    http = HttpLayer()
    http.execute_client()


if __name__ == "__main__":
    main()
