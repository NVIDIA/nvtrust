#
#  Copyright (c) 2023  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
AMD_SEV_DIR=/shared/AMDSEV/snp-release-2023-07-19
VDD_IMAGE=/shared/nvtrust/host_tools/sample_kvm_scripts/images/ubuntu22.04.qcow2
ISO=/shared/nvtrust/host_tools/sample_kvm_scripts/isos/ubuntu-22.04.2-live-server-amd64.iso
FWDPORT=9899

$AMD_SEV_DIR/usr/local/bin/qemu-system-x86_64 \
-enable-kvm -nographic -no-reboot -cpu EPYC-v4 -machine q35 \
-smp 12,maxcpus=31 -m 64G,slots=5,maxmem=120G \
-drive if=pflash,format=raw,unit=0,file=$AMD_SEV_DIR/usr/local/share/qemu/OVMF_CODE.fd,readonly=on \
-drive file=$VDD_IMAGE,if=none,id=disk0,format=qcow2 \
-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
-device scsi-hd,drive=disk0 \
-device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
-netdev user,id=vmnic,hostfwd=tcp::$FWDPORT-:22 \
-cdrom $ISO
