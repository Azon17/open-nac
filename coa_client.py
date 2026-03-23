"""
CoA Client — отправка Change of Authorization на NAD.
"""

import asyncio
import logging

logger = logging.getLogger("nac.coa")


class CoAClient:
    def __init__(self, secret: str = "changeme_coa_secret"):
        self.secret = secret

    async def send_reauth(self, nas_ip: str, mac: str, session_id: str = "") -> dict:
        attrs = [
            f"Calling-Station-Id={mac}",
            'Cisco-AVPair="subscriber:command=reauthenticate"',
        ]
        if session_id:
            attrs.append(f"Acct-Session-Id={session_id}")
        return await self._radclient(nas_ip, "coa", attrs)

    async def send_disconnect(self, nas_ip: str, mac: str, session_id: str = "") -> dict:
        attrs = [f"Calling-Station-Id={mac}"]
        if session_id:
            attrs.append(f"Acct-Session-Id={session_id}")
        return await self._radclient(nas_ip, "disconnect", attrs)

    async def send_bounce(self, nas_ip: str, mac: str) -> dict:
        attrs = [
            f"Calling-Station-Id={mac}",
            'Cisco-AVPair="subscriber:command=bounce-host-port"',
        ]
        return await self._radclient(nas_ip, "coa", attrs)

    async def _radclient(self, nas_ip: str, pkt_type: str, attrs: list) -> dict:
        attr_str = "\n".join(attrs)
        cmd = f'echo "{attr_str}" | radclient -t 5 {nas_ip}:3799 {pkt_type} {self.secret}'
        try:
            proc = await asyncio.create_subprocess_shell(
                cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE,
            )
            stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=10)
            success = proc.returncode == 0
            logger.info(f"CoA {pkt_type} -> {nas_ip}: {'ACK' if success else 'NAK'} mac={attrs[0]}")
            return {"success": success, "output": stdout.decode().strip(), "error": stderr.decode().strip()}
        except Exception as e:
            logger.error(f"CoA failed: {e}")
            return {"success": False, "error": str(e)}


coa_client = CoAClient()
