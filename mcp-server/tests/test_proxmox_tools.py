import pytest
from unittest.mock import AsyncMock, patch
from src.server import (
    get_proxmox_cluster_status,
    get_proxmox_vms,
    get_proxmox_vm_status,
    get_proxmox_storage_status,
)


@pytest.mark.asyncio
async def test_proxmox_unconfigured():
    with patch("src.server.proxmox_manager.is_configured", return_value=False):
        res = await get_proxmox_cluster_status()
        assert "error" in res
        assert "Proxmox credentials not configured" in res["error"]


@pytest.mark.asyncio
async def test_get_proxmox_cluster_status_success():
    mock_nodes = [
        {
            "node": "pve",
            "status": "online",
        }
    ]
    mock_node_detail = {
        "cpu": 0.125,
        "pveversion": "pve-manager/9.2.2",
        "kversion": "Linux 7.0.2-6-pve",
        "cpuinfo": {
            "model": "Intel(R) Core(TM) i7-6700K CPU @ 4.00GHz",
            "cores": 4,
            "cpus": 8,
        },
        "loadavg": ["0.40", "0.56", "0.65"],
        "memory": {
            "total": 64 * (1024**3),
            "used": 16 * (1024**3),
        },
        "rootfs": {
            "total": 500 * (1024**3),
            "used": 100 * (1024**3),
        },
        "uptime": 86400,
    }

    with patch("src.server.proxmox_manager.is_configured", return_value=True), \
         patch("src.server.proxmox_manager.get_nodes", new_callable=AsyncMock, return_value=mock_nodes), \
         patch("src.server.proxmox_manager.get_node_status", new_callable=AsyncMock, return_value=mock_node_detail):
        res = await get_proxmox_cluster_status()
        assert res["node_count"] == 1
        node = res["nodes"][0]
        assert node["node"] == "pve"
        assert node["status"] == "online"
        assert node["cpu_utilization_pct"] == 12.5
        assert node["memory_total_gb"] == 64.0
        assert node["memory_used_gb"] == 16.0
        assert node["memory_utilization_pct"] == 25.0
        assert node["uptime_days"] == 1.0


@pytest.mark.asyncio
async def test_get_proxmox_vms_success():
    mock_vms = [
        {
            "vmid": 100,
            "name": "jarvis-siem",
            "status": "running",
            "node": "pve",
            "cpu": 0.05,
            "mem": 8 * (1024**3),
            "maxmem": 16 * (1024**3),
            "uptime": 43200,
        },
        {
            "vmid": 101,
            "name": "jarvis-gpu",
            "status": "running",
            "node": "pve",
            "cpu": 0.35,
            "mem": 16 * (1024**3),
            "maxmem": 32 * (1024**3),
            "uptime": 43200,
        },
    ]

    with patch("src.server.proxmox_manager.is_configured", return_value=True), \
         patch("src.server.proxmox_manager.get_cluster_resources", new_callable=AsyncMock, return_value=mock_vms):
        res = await get_proxmox_vms()
        assert res["total_vms"] == 2
        assert res["vms"][0]["name"] == "jarvis-siem"
        assert res["vms"][1]["name"] == "jarvis-gpu"


@pytest.mark.asyncio
async def test_get_proxmox_vm_status_success():
    mock_resources = [{"vmid": 100, "node": "pve"}]
    mock_vm_status = {
        "name": "jarvis-siem",
        "status": "running",
        "qmpstatus": "running",
        "cpu": 0.082,
        "mem": 6 * (1024**3),
        "maxmem": 16 * (1024**3),
        "diskread": 1024000,
        "diskwrite": 5120000,
        "netin": 20480000,
        "netout": 4096000,
        "uptime": 12345,
    }

    with patch("src.server.proxmox_manager.is_configured", return_value=True), \
         patch("src.server.proxmox_manager.get_cluster_resources", new_callable=AsyncMock, return_value=mock_resources), \
         patch("src.server.proxmox_manager.get_vm_status", new_callable=AsyncMock, return_value=mock_vm_status):
        res = await get_proxmox_vm_status(vmid=100)
        assert res["vmid"] == 100
        assert res["name"] == "jarvis-siem"
        assert res["status"] == "running"
        assert res["cpu_utilization_pct"] == 8.2


@pytest.mark.asyncio
async def test_get_proxmox_storage_status_success():
    mock_storages = [
        {
            "storage": "local-zfs",
            "type": "zfspool",
            "node": "pve",
            "status": "available",
            "maxdisk": 11500 * (1024**3),  # 11.5 TB
            "disk": 1500 * (1024**3),
            "content": "images,rootdir",
        }
    ]

    with patch("src.server.proxmox_manager.is_configured", return_value=True), \
         patch("src.server.proxmox_manager.get_cluster_resources", new_callable=AsyncMock, return_value=mock_storages):
        res = await get_proxmox_storage_status()
        assert res["total_pools"] == 1
        pool = res["storage_pools"][0]
        assert pool["storage"] == "local-zfs"
        assert pool["type"] == "zfspool"
        assert pool["total_gb"] == 11500.0
        assert pool["used_pct"] == 13.04
