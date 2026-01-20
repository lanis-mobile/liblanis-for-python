import json
from importlib.metadata import version
from importlib.metadata import Distribution


__version__ = version("liblanis")

__direct_url = Distribution.from_name("liblanis").read_text("direct_url.json")
__isDev__ = json.loads(__direct_url).get("dir_info", {}).get("editable", False)
