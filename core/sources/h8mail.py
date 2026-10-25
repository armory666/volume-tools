import asyncio
import os
import tempfile
from core.models import Hit

class H8Mail:
    name = "h8mail"
    accepts = ("email",)
    free = True
    pillar = "breach"

    async def query(self, seed, kind):
        if kind != "email":
            return []
        
        # h8mail outputs to a JSON file, we pass it a temp path
        fd, temp_path = tempfile.mkstemp()
        os.close(fd)
        
        try:
            proc = await asyncio.create_subprocess_exec(
                "h8mail", "-t", seed, "-o", temp_path, "-j",
                stdout=asyncio.subprocess.DEVNULL,
                stderr=asyncio.subprocess.DEVNULL,
            )
            await asyncio.wait_for(proc.communicate(), timeout=45)
            
            if not os.path.exists(temp_path) or os.path.getsize(temp_path) == 0:
                return []
                
            import json
            with open(temp_path, "r") as f:
                data = json.load(f)
                
            hits = []
            # h8mail JSON structure is a list of dicts
            for entry in data:
                # check if it's a breach hit
                if "breach" in entry or "source" in entry:
                    hits.append(Hit(self.name, "h8_breach", entry.get("breach", "unknown"), {
                        "source": entry.get("source"),
                        "password": entry.get("password", "hidden")
                    }))
            return hits
            
        except Exception:
            return []
        finally:
            if os.path.exists(temp_path):
                os.remove(temp_path)
