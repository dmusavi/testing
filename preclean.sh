#!/bin/bash
# -----------------------------------------------------------------------------
# Set strict error handling
set -euo pipefail  # Exit immediately on error, treat unset variables as errors, and ensure correct handling of pipes
IFS=$'\n\t'       # Set Internal Field Separator for handling newlines and tabs

# -----------------------------------------------------------------------------
# Variables
EXPECTED_CHECKSUM="SHA256_CHECKSUM_HERE"   # Expected SHA256 checksum for verification (replace with actual checksum)
IMAGE_ID="arch-container"                  # Container ID for crun
NETNS_NAME="arch-netns"                    # Network namespace name
BRIDGE_NAME="br0"                          # Bridge name (brought up by init systemv ifup br0)
BRIDGE_IP="10.10.10.14/24"                  # IP address for the bridge network
CONTAINER_IP="10.0.20.1/24"                 # IP address for the container within its network
HOST_PORT="8088"                           # Host port for container port forwarding
CONTAINER_PORT="80"                        # Container port

BASE_DIR="$HOME/downloads/media/config/nginx"
HOST_CONFIG_DIR="$BASE_DIR"                # Directory for Nginx configuration on the host
HOST_NGINX_CONF="$HOST_CONFIG_DIR/nginx.conf"  # Path to Nginx configuration on the host
HOST_MEDIA_DIR="$HOST_CONFIG_DIR/media"    # Directory for media files to be served by Nginx on the host

# URLs for the bootstrap tarball, its signature, and the checksum file
IMAGE_URL_ARCH="https://geo.mirror.pkgbuild.com/iso/2025.02.01/archlinux-bootstrap-2025.02.01-x86_64.tar.zst"
IMAGE_SIG_URL="https://geo.mirror.pkgbuild.com/iso/2025.02.01/archlinux-bootstrap-2025.02.01-x86_64.tar.zst.sig"
CHECKSUMS_URL="https://archlinux.org/iso/2025.02.01/sha256sums.txt"

# The tarball filename
IMAGE_FILE="archlinux-bootstrap-2025.02.01-x86_64.tar.zst"

# Directories for downloads and bundle extraction
DOWNLOAD_DIR="$BASE_DIR/downloads"
BUNDLE_DIR="$BASE_DIR"

# -----------------------------------------------------------------------------
# BEGIN: log function
# Function to log informational messages.
log() {
    echo "[INFO] $1"
}
# END: log function

# -----------------------------------------------------------------------------
# BEGIN: error_exit function
# Function to handle errors by printing a message and exiting.
error_exit() {
    echo "[ERROR] $1" >&2
    exit 1
}
# END: error_exit function

# -----------------------------------------------------------------------------
# BEGIN: precleanup function
# Function to clean up any leftovers from previous runs, including legacy cgroup v1.
precleanup() {
    log "Performing pre-cleanup of previous resources..."
    
    # Clean up legacy cgroup v1 directories
    log "Cleaning up legacy cgroup v1 directories..."
    local controllers=(cpuset cpu cpuacct memory devices freezer net_cls blkio)
    for subsys in "${controllers[@]}"; do
        if mountpoint -q "/sys/fs/cgroup/$subsys"; then
            log "Unmounting legacy cgroup v1 controller: $subsys..."
            sudo umount "/sys/fs/cgroup/$subsys" 2>/dev/null || true
        fi
        if [ -d "/sys/fs/cgroup/$subsys" ]; then
            log "Removing legacy cgroup directory: /sys/fs/cgroup/$subsys..."
            sudo rmdir "/sys/fs/cgroup/$subsys" 2>/dev/null || true
        fi
    done

    log "Pre-cleanup completed."
}
# END: precleanup function

# -----------------------------------------------------------------------------
# BEGIN: prepare_cgroup_filesystem function
# Function to check and prepare the cgroup v2 filesystem.
prepare_cgroup_filesystem() {
    log "Preparing cgroup v2 filesystem..."

    # Unmount any existing mount at /sys/fs/cgroup (up to 5 attempts)
    for i in {1..5}; do
        if mountpoint -q /sys/fs/cgroup; then
            log "Unmounting existing cgroup mount (attempt $i)..."
            sudo umount /sys/fs/cgroup || break
        else
            break
        fi
    done

    # Create mount point if not present and mount cgroup v2 using the proper source name "cgroup2"
    if ! mountpoint -q /sys/fs/cgroup; then
        log "Creating cgroup mount point..."
        sudo mkdir -p /sys/fs/cgroup
        log "Mounting cgroup v2 filesystem..."
        sudo mount -t cgroup2 cgroup2 /sys/fs/cgroup || error_exit "Failed to mount cgroup v2 filesystem"
    fi

    # Ensure proper permissions on the cgroup mountpoint
    sudo chmod 755 /sys/fs/cgroup
    sudo chown root:root /sys/fs/cgroup

    # Create container-specific cgroup directory
    CONTAINER_CGROUP="/sys/fs/cgroup/container-${IMAGE_ID}"
    sudo mkdir -p "$CONTAINER_CGROUP"
    sudo chown -R root:root "$CONTAINER_CGROUP"
    sudo chmod -R 755 "$CONTAINER_CGROUP"

    # Modify config.json cgroupsPath if the file exists
    local config_file="$BUNDLE_DIR/config.json"
    if [ -f "$config_file" ]; then
        sed -i "s|\"cgroupsPath\": \"/sys/fs/cgroup\"|\"cgroupsPath\": \"$CONTAINER_CGROUP\"|g" "$config_file"
    fi

    # Verify that the mount is in place
    if ! mountpoint -q /sys/fs/cgroup; then
        error_exit "Failed to mount cgroup v2 filesystem"
    fi

    log "Cgroup v2 filesystem prepared successfully"
}
# END: prepare_cgroup_filesystem function

# -----------------------------------------------------------------------------
# BEGIN: cleanup_cgroups function
# Function to clean up container-specific cgroups.
cleanup_cgroups() {
    log "Cleaning up container-specific cgroups..."

    # Remove container-specific cgroup directory if it exists
    if [ -d "$CONTAINER_CGROUP" ]; then
        sudo rmdir "$CONTAINER_CGROUP" 2>/dev/null || true
    fi

    # Kill any processes that remain in the container-specific cgroup
    local cgroup_procs="/sys/fs/cgroup/container-${IMAGE_ID}/cgroup.procs"
    if [ -f "$cgroup_procs" ]; then
        while read -r pid; do
            sudo kill -9 "$pid" 2>/dev/null || true
        done < "$cgroup_procs"
    fi
}
# END: cleanup_cgroups function

# -----------------------------------------------------------------------------
# BEGIN: cleanup function
# Modified cleanup function that calls cleanup_cgroups and performs additional cleanup.
cleanup() {
    local exit_code=$?
    log "Performing cleanup..."

    cleanup_cgroups       # Clean up container-specific cgroup resources

    # Existing cleanup code:
    if sudo crun list | grep -qw "$IMAGE_ID"; then
        sudo crun stop "$IMAGE_ID" 2>/dev/null || true
        sudo crun delete -f "$IMAGE_ID" 2>/dev/null || true
    fi

    if sudo ip netns list | grep -qw "$NETNS_NAME"; then
        sudo ip netns del "$NETNS_NAME" 2>/dev/null || true
    fi

    if ip link show veth1 &>/dev/null; then
        sudo ip link delete veth1 2>/dev/null || true
    fi

    sudo rm -rf "$DOWNLOAD_DIR" "$BUNDLE_DIR"
    rm -f "/tmp/container_$IMAGE_ID.pid"

    exit "$exit_code"
}
# END: cleanup function

# ... (rest of the script remains unchanged)

# -----------------------------------------------------------------------------
# BEGIN: main function
# Main function to orchestrate the container setup.
main() {
    precleanup                 # Clean up leftovers from previous runs
    check_dependencies          # Check for required dependencies
    create_directories          # Create necessary directories
    download_verify_image       # Download and verify the Arch Linux image
    create_nginx_config         # Create Nginx configuration
    create_container_config     # Create container configuration
    setup_networking            # Set up networking for the container
    check_cgroup_version        # Check the current cgroup version
    prepare_cgroup_filesystem   # Prepare the cgroup v2 filesystem and update config.json
    start_container             # Start the container

    log "Container started with port forwarding from host $HOST_PORT to container $CONTAINER_PORT."
}
# END: main function

# -----------------------------------------------------------------------------
# Invoke the main function with any provided arguments.
main "$@"
