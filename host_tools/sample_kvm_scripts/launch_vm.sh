#
#  Copyright (c) 2023  NVIDIA CORPORATION & AFFILIATES. All rights reserved.
#
AMD_SEV_DIR=/shared/AMDSEV/snp-release-2023-07-18
VDD_IMAGE=/shared/nvtrust/host_tools/sample_kvm_scripts/images/ubuntu22.04.qcow2

#Hardware Settings
NVIDIA_GPU=45:00.0
MEM=64 #in GBs
FWDPORT=9899

doecho=false
docc=true

while getopts "exp:" flag
do
        case ${flag} in
                e) doecho=true;;
                x) docc=false;;
                p) FWDPORT=${OPTARG};;
        esac
done

NVIDIA_GPU=$(lspci -d 10de: | awk '/NVIDIA/{print $1}')
NVIDIA_PASSTHROUGH=$(lspci -n -s $NVIDIA_GPU | awk -F: '{print $4}' | awk '{print $1}')

if [ "$doecho" = true ]; then
         echo 10de $NVIDIA_PASSTHROUGH > /sys/bus/pci/drivers/vfio-pci/new_id
fi

if [ "$docc" = true ]; then
        USE_HCC=true
fi

$AMD_SEV_DIR/usr/local/bin/qemu-system-x86_64 \
${USE_HCC:+ -machine confidential-guest-support=sev0,vmport=off} \
${USE_HCC:+ -object sev-snp-guest,id=sev0,cbitpos=51,reduced-phys-bits=1} \
-enable-kvm -nographic -no-reboot \
-cpu EPYC-v4 -machine q35 -smp 12,maxcpus=31 -m ${MEM}G,slots=2,maxmem=512G \
-drive if=pflash,format=raw,unit=0,file=$AMD_SEV_DIR/usr/local/share/qemu/OVMF_CODE.fd,readonly=on \
-drive file=$VDD_IMAGE,if=none,id=disk0,format=qcow2 \
-device virtio-scsi-pci,id=scsi0,disable-legacy=on,iommu_platform=true \
-device scsi-hd,drive=disk0 \
-device virtio-net-pci,disable-legacy=on,iommu_platform=true,netdev=vmnic,romfile= \
-netdev user,id=vmnic,hostfwd=tcp::$FWDPORT-:22 \
-device pcie-root-port,id=pci.1,bus=pcie.0 \
-device vfio-pci,host=$NVIDIA_GPU,bus=pci.1 \
-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=262144

