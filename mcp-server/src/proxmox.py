"""Proxmox VE REST API client manager.

Connects to the Proxmox VE API to query node health, VM/LXC statuses,
PCIe devices, and ZFS/storage pool metrics.
"""

import os
from pathlib import Path
from typing import Any, Dict, List, Optional
import httpx
from dotenv import load_dotenv

load_dotenv(Path(__file__).resolve().parent.parent / ".env")
load_dotenv()


class ProxmoxClientManager:
    """Manages asynchronous communication with the Proxmox VE REST API."""

    def __init__(
        self,
        host: Optional[str] = None,
        port: Optional[int] = None,
        token_id: Optional[str] = None,
        token_secret: Optional[str] = None,
        user: Optional[str] = None,
        password: Optional[str] = None,
        verify_ssl: bool = False,
    ):
        self.host = host or os.getenv("PROXMOX_HOST", os.getenv("ELASTIC_HOST", "10.0.0.20"))
        self.port = port or int(os.getenv("PROXMOX_PORT", "8006"))
        self.token_id = token_id or os.getenv("PROXMOX_TOKEN_ID")
        self.token_secret = token_secret or os.getenv("PROXMOX_TOKEN_SECRET")
        self.user = user or os.getenv("PROXMOX_USER")
        self.password = password or os.getenv("PROXMOX_PASSWORD")
        self.verify_ssl = verify_ssl or (os.getenv("PROXMOX_VERIFY_SSL", "false").lower() == "true")

        self.base_url = f"https://{self.host}:{self.port}/api2/json"
        self._ticket: Optional[str] = None
        self._csrf_token: Optional[str] = None

    def _get_formatted_token_id(self) -> Optional[str]:
        if not self.token_id:
            return None
        if "!" in self.token_id:
            return self.token_id
        user = self.user or "root@pam"
        if "@" not in user:
            user = f"{user}@pve"
        return f"{user}!{self.token_id}"

    def _get_headers(self) -> Dict[str, str]:
        headers = {"Accept": "application/json"}
        formatted_token = self._get_formatted_token_id()
        if formatted_token and self.token_secret:
            headers["Authorization"] = f"PVEAPIToken={formatted_token}={self.token_secret}"
        elif self._ticket:
            headers["Cookie"] = f"PVEAuthCookie={self._ticket}"
            if self._csrf_token:
                headers["CSRFPreventionToken"] = self._csrf_token
        return headers

    def is_configured(self) -> bool:
        """Check if either API token or user credentials are provided."""
        return bool((self.token_id and self.token_secret) or (self.user and self.password))

    async def _ensure_ticket_authenticated(self, client: httpx.AsyncClient):
        """Authenticate via ticket using username and password."""
        if self._ticket:
            return
        if not (self.user and self.password):
            raise ValueError(
                "Proxmox credentials not configured. Please set PROXMOX_TOKEN_ID and PROXMOX_TOKEN_SECRET "
                "or PROXMOX_USER and PROXMOX_PASSWORD."
            )

        username = self.user
        if "@" not in username:
            username = f"{username}@pve"

        resp = await client.post(
            f"{self.base_url}/access/ticket",
            data={"username": username, "password": self.password},
        )
        resp.raise_for_status()
        data = resp.json().get("data", {})
        self._ticket = data.get("ticket")
        self._csrf_token = data.get("CSRFPreventionToken")

    async def _get(self, endpoint: str, params: Optional[Dict[str, Any]] = None) -> Any:
        """Execute authenticated GET request to Proxmox API with fallback."""
        async with httpx.AsyncClient(verify=self.verify_ssl, timeout=10.0) as client:
            url = f"{self.base_url}/{endpoint.lstrip('/')}"

            # 1. Try Token Auth if configured
            formatted_token = self._get_formatted_token_id()
            if formatted_token and self.token_secret:
                headers = {
                    "Accept": "application/json",
                    "Authorization": f"PVEAPIToken={formatted_token}={self.token_secret}",
                }
                resp = await client.get(url, headers=headers, params=params)
                if resp.status_code == 200:
                    result = resp.json()
                    data = result.get("data", [])
                    # If data is non-empty, or if no user/pass fallback available, return token data
                    if data or not (self.user and self.password):
                        return data
                elif resp.status_code != 403 or not (self.user and self.password):
                    resp.raise_for_status()

            # 2. Ticket Auth fallback
            await self._ensure_ticket_authenticated(client)
            headers = {
                "Accept": "application/json",
                "Cookie": f"PVEAuthCookie={self._ticket}",
            }
            if self._csrf_token:
                headers["CSRFPreventionToken"] = self._csrf_token
            resp = await client.get(url, headers=headers, params=params)
            resp.raise_for_status()
            result = resp.json()
            return result.get("data", [])


    async def get_nodes(self) -> List[Dict[str, Any]]:
        """Retrieve list of Proxmox cluster nodes and high-level health."""
        return await self._get("/nodes")

    async def get_node_status(self, node: str) -> Dict[str, Any]:
        """Retrieve detailed resource utilization for a specific node."""
        return await self._get(f"/nodes/{node}/status")

    async def get_cluster_resources(self, resource_type: Optional[str] = None) -> List[Dict[str, Any]]:
        """Retrieve cluster resources (vms, nodes, storages, pools)."""
        params = {"type": resource_type} if resource_type else None
        return await self._get("/cluster/resources", params=params)

    async def get_node_vms(self, node: str) -> List[Dict[str, Any]]:
        """Retrieve all QEMU VMs on a given node."""
        return await self._get(f"/nodes/{node}/qemu")

    async def get_vm_status(self, node: str, vmid: int) -> Dict[str, Any]:
        """Retrieve real-time status of a specific VM."""
        return await self._get(f"/nodes/{node}/qemu/{vmid}/status/current")

    async def get_storage_status(self, node: str) -> List[Dict[str, Any]]:
        """Retrieve status of all storage pools (ZFS, LVM, Directory) on a node."""
        return await self._get(f"/nodes/{node}/storage")

