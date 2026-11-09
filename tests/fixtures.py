import base64


def legacy_state():
    def key(number):
        return base64.b64encode(bytes([number]) * 32).decode()

    return {
        "version": 1, "instance": "main", "endpoint": "93.184.216.34",
        "port": 56001, "backend_port": 51830, "subnet": "10.77.43.0/24", "wan": "eth0",
        "obf_key": "a" * 64, "server_private": key(1), "server_public": key(2),
        "vk_link": "https://vk.ru/call/join/synthetic-test-only",
        "clients": {name: {"private_key": key(i), "public_key": key(i + 1),
                           "preshared_key": key(i + 2), "cid": str(i) * 32}
                    for name, i in [("iphone", 3), ("android", 6)]},
    }
