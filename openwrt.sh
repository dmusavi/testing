#!/bin/bash
set -e  # Exit on any error

# List of required commands/dependencies
REQUIRED_CMDS=(
    gcc g++ make ld ar ranlib strip git flex bison \
    python3 perl patch rsync unzip wget gunzip \
    bash xz gzip bzip2 zip \
    ncurses5-config
)

# Function to check for dependencies
check_dependencies() {
    MISSING_CMDS=()
    for cmd in "${REQUIRED_CMDS[@]}"; do
        if ! command -v "$cmd" &>/dev/null; then
            MISSING_CMDS+=("$cmd")
        fi
    done

    if [ "${#MISSING_CMDS[@]}" -ne 0 ]; then
        echo "Error: The following required commands are missing:"
        for cmd in "${MISSING_CMDS[@]}"; do
            echo "  - $cmd"
        done
        echo "Please install them before running this script."
        exit 1
    fi

    # Check for libncurses
    if ! ldconfig -p | grep -q "libncurses"; then
        echo "Error: libncurses not found."
        echo "Please install libncurses to proceed."
        exit 1
    fi

    # Check for zlib
    if ! ldconfig -p | grep -q "libz.so"; then
        echo "Error: zlib library not found."
        echo "Please install zlib to proceed."
        exit 1
    fi
}

# Run dependency check
check_dependencies

# Define user variables
USER_HOME="/home/yourusername"   # Replace with your actual username
OPENWRT_URL="https://github.com/openwrt/openwrt.git"
OPENWRT_DIR="$USER_HOME/openwrt"
CONFIG_FILE="$USER_HOME/bananapi_rpi4_wifi7.config"
IMAGE_PATH="$OPENWRT_DIR/bin/targets/mediatek/filogic/openwrt-mediatek-filogic-bananapi_bpi-r4-sdcard.img.gz"
DEVICE="$1"

# Check for device argument
if [ -z "$DEVICE" ]; then
    echo "Usage: sudo $0 <device_path>"
    exit 1
fi

# Check if config file exists
if [ ! -f "$CONFIG_FILE" ]; then
    echo "Error: Config file not found: $CONFIG_FILE"
    echo "Please create it with WiFi 7 support for Banana Pi RPi-4."
    exit 1
fi

# Clone or update OpenWRT repository
echo "Cloning or updating OpenWRT repository..."
if [ -d "$OPENWRT_DIR" ]; then
    cd "$OPENWRT_DIR"
    git pull || { echo "Error: Failed to update repository."; exit 1; }
else
    git clone "$OPENWRT_URL" "$OPENWRT_DIR" || { echo "Error: Failed to clone repository."; exit 1; }
    cd "$OPENWRT_DIR"
fi

# Update and install feeds
echo "Updating and installing package feeds..."
./scripts/feeds update -a
./scripts/feeds install -a

# Configure the build
echo "Configuring build..."
cp "$CONFIG_FILE" .config
make defconfig

# Compile the image
echo "Compiling OpenWRT image (this may take a while)..."
make -j$(nproc)

# Check if the image file exists
if [ ! -f "$IMAGE_PATH" ]; then
    echo "Error: Image file not found at $IMAGE_PATH"
    exit 1
fi

# Ensure the script is run as root from here on
if [ "$(id -u)" != "0" ]; then
    echo "Please run the script with sudo when flashing the device."
    exit 1
fi

# Check if device exists
if [ ! -b "$DEVICE" ]; then
    echo "Error: Device not found: $DEVICE"
    exit 1
fi

# Confirm device
echo "You are about to write to $DEVICE:"
lsblk "$DEVICE"
echo "Type 'yes' to confirm and proceed:"
read -r confirm
if [ "$confirm" != "yes" ]; then
    echo "Aborted."
    exit 1
fi

# Unmount any partitions
echo "Unmounting any partitions on $DEVICE..."
for partition in $(lsblk -ln -o NAME "$DEVICE" | tail -n +2); do
    mountpoint=$(findmnt -n "/dev/$partition" | awk '{print $2}')
    if [ -n "$mountpoint" ]; then
        umount "/dev/$partition"
        echo "Unmounted /dev/$partition from $mountpoint"
    fi
done

# Write the image to the device (handling compressed image)
echo "Writing OpenWRT image to $DEVICE..."
gunzip -c "$IMAGE_PATH" | dd of="$DEVICE" bs=4M conv=fsync status=progress

# Ensure data is written
sync

echo "Installation complete."