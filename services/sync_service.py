
import json
import shutil
import subprocess
from pathlib import Path
from urllib.request import urlopen, Request


class SyncService:
    """Zero-cost sync helper using Syncthing."""

    def __init__(self, config_path="config/sync_config.json"):
        self.config_path = Path(config_path)
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        if not self.config_path.exists():
            self._save({"sync_folder": "", "enabled": False})

    def _load(self):
        try:
            return json.loads(self.config_path.read_text(encoding="utf-8"))
        except Exception:
            return {"sync_folder": "", "enabled": False}

    def _save(self, data):
        self.config_path.write_text(json.dumps(data, indent=2), encoding="utf-8")

    def set_sync_folder(self, folder):
        p = Path(folder).expanduser().resolve()
        p.mkdir(parents=True, exist_ok=True)
        cfg = self._load()
        cfg["sync_folder"] = str(p)
        cfg["enabled"] = True
        self._save(cfg)
        return str(p)

    def get_sync_folder(self):
        return self._load().get("sync_folder", "")

    def is_syncthing_installed(self):
        return shutil.which("syncthing") is not None

    def launch_syncthing(self):
        if not self.is_syncthing_installed():
            return False, "Syncthing not found in PATH"
        try:
            subprocess.Popen(
                ["syncthing", "-no-browser"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
                start_new_session=True
            )
            return True, "Syncthing launch requested"
        except FileNotFoundError:
            return False, "Syncthing not found in PATH"
        except Exception as e:
            return False, str(e)

    def is_syncthing_running(self):
        # Syncthing local API health endpoint
        try:
            req = Request("http://127.0.0.1:8384/rest/noauth/health")
            with urlopen(req, timeout=1.5) as resp:
                return resp.status == 200
        except Exception:
            return False

    def setup_steps(self):
        return [
            "Install Syncthing on each device.",
            "Set your vault sync folder in this app.",
            "Open Syncthing web UI and add the same folder on other devices.",
            "Pair devices using Syncthing device IDs.",
            "Let Syncthing sync encrypted vault data directly P2P.",
        ]
