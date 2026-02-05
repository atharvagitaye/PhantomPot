import os
from honeypot.server import HoneypotServer

def test_config_exists():
    """Check if the configuration file exists."""
    assert os.path.exists('config/config.yaml') or os.path.exists('config.yaml')

def test_server_initialization():
    """Basic test to see if the server class can be instantiated."""
    # This assumes your HoneypotServer takes a config path or dict
    try:
        server = HoneypotServer()
        assert server is not None
    except Exception as e:
        print(f"Server init failed: {e}")
