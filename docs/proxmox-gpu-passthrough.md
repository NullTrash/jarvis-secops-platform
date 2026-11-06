# Proxmox VE: PCIe GPU Passthrough & Docker CUDA Setup Guide

This guide walks you through dedicating a physical GPU on your Proxmox VE host to your 24/7 **`jarvis-gpu`** VM (VM 2).

---

## 1. Enable IOMMU in Proxmox Host (PVE)

1. Open a shell on your Proxmox VE host (via Web Console or SSH as `root`).
2. Edit GRUB configuration:
   ```bash
   nano /etc/default/grub
   ```
3. Find `GRUB_CMDLINE_LINUX_DEFAULT` and enable IOMMU:
   * **For Intel CPUs**:
     ```ini
     GRUB_CMDLINE_LINUX_DEFAULT="quiet intel_iommu=on iommu=pt pcie_acs_override=downstream,multifunction"
     ```
   * **For AMD CPUs**:
     ```ini
     GRUB_CMDLINE_LINUX_DEFAULT="quiet amd_iommu=on iommu=pt pcie_acs_override=downstream,multifunction"
     ```
4. Update GRUB and reboot the Proxmox host:
   ```bash
   update-grub
   reboot
   ```

---

## 2. Load VFIO Modules on Proxmox Host

1. Edit `/etc/modules`:
   ```bash
   nano /etc/modules
   ```
   Add the following lines:
   ```text
   vfio
   vfio_iommu_type1
   vfio_pci
   vfio_virqfd
   ```

2. Blacklist default GPU drivers on the PVE host (so the host does not grab the GPU on boot):
   ```bash
   nano /etc/modprobe.d/blacklist.conf
   ```
   Add:
   ```text
   blacklist nouveau
   blacklist nvidia
   blacklist nvidiafb
   blacklist radeon
   ```

3. Update initramfs:
   ```bash
   update-initramfs -u -k all
   ```

---

## 3. Attach GPU to VM 2 (`jarvis-gpu`) in Proxmox Web GUI

1. Select your GPU VM (`jarvis-gpu`) in the Proxmox left sidebar.
2. Go to **Hardware** $\rightarrow$ **Add** $\rightarrow$ **PCI Device**.
3. Select **Raw Device**:
   * Choose your NVIDIA GPU device (e.g., `0000:01:00.0`).
   * Check **All Functions** (to pass both GPU and Audio controller).
   * Check **Primary GPU** (if you want it to act as primary, or uncheck and keep default display).
   * Check **PCI-Express**.
4. In VM **Options**, set **BIOS** to `OVMF (UEFI)` and **Machine** to `q35`.
5. Start the VM.

---

## 4. Inside the `jarvis-gpu` Linux VM (Docker + CUDA)

Once inside the Ubuntu/Debian VM:

1. Install NVIDIA Drivers:
   ```bash
   sudo apt update
   sudo apt install -y build-essential dkms linux-headers-$(uname -r)
   sudo apt install -y nvidia-driver-550
   ```
2. Verify GPU detection:
   ```bash
   nvidia-smi
   ```
3. Install NVIDIA Container Toolkit (allows Docker to access GPU):
   ```bash
   curl -fsSL https://nvidia.github.io/libnvidia-container/gpgkey | sudo gpg --dearmor -o /usr/share/keyrings/nvidia-container-toolkit-keyring.gpg
   curl -s -L https://nvidia.github.io/libnvidia-container/stable/deb/nvidia-container-toolkit.list | \
     sed 's#deb https://#deb [signed-by=/usr/share/keyrings/nvidia-container-toolkit-keyring.gpg] https://#g' | \
     sudo tee /etc/apt/sources.list.d/nvidia-container-toolkit.list
   sudo apt update
   sudo apt install -y nvidia-container-toolkit
   sudo nvidia-ctk runtime configure --runtime=docker
   sudo systemctl restart docker
   ```
4. Start the Jarvis GPU Docker Stack:
   ```bash
   cd docker/gpu-compute
   docker compose up -d
   ./scripts/bootstrap-models.sh
   ```
