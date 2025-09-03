import yaml
from honeypot.protocols.ssh import SSHHoneypot

def load_config(path="honeypot/config.yaml"):
    with open(path, "r") as f:
        return yaml.safe_load(f)

if __name__ == "__main__":
    config = load_config()

    ssh_conf = config["honeypot"]["ssh"]
    log_file = config["logging"]["log_file"]

    if ssh_conf["enabled"]:
        ssh_honeypot = SSHHoneypot(
            host="0.0.0.0",
            port=ssh_conf["port"],
            log_file=log_file
        )
        ssh_honeypot.start()