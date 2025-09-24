import yaml
from honeypot.protocols.http import HTTPHoneypot

def load_config(path="honeypot/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    config = load_config()
    http_conf = config["honeypot"].get("http", {})
    if http_conf.get("enabled", False):
        http_honeypot = HTTPHoneypot(
            host="0.0.0.0",
            port=http_conf.get("port", 8080)
        )
        try:
            http_honeypot.run()
        except KeyboardInterrupt:
            print("\n[!] KeyboardInterrupt received. Shutting down HTTP honeypot...")
