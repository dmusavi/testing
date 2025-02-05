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
BRIDGE_IP="10.10.10.14/24"                # IP address for the bridge network
CONTAINER_IP="10.0.20.1/24"               # IP address for the container within its network
HOST_PORT="8088"                           # Host port for container port forwarding
CONTAINER_PORT="80"                        # Container port

BASE_DIR="$HOME/downloads/media/config/nginx"
HOST_CONFIG_DIR="$BASE_DIR"                # Directory for Nginx configuration on the host
HOST_NGINX_CONF="$HOST_CONFIG_DIR/nginx.conf"  # Path to Nginx configuration on the host
HOST_MEDIA_DIR="$HOST_CONFIG_DIR/media"    # Directory for media files to be served by Nginx on the host

IMAGE_URL_ARCH="https://geo.mirror.pkgbuild.com/iso/2025.02.01/archlinux-bootstrap-2025.02.01-x86_64.tar.zst"
IMAGE_SIG_URL="https://geo.mirror.pkgbuild.com/iso/2025.02.01/archlinux-bootstrap-2025.02.01-x86_64.tar.zst.sig"
CHECKSUMS_URL="https://archlinux.org/iso/2025.02.01/sha256sums.txt"

IMAGE_FILE="archlinux-bootstrap-2025.02.01-x86_64.tar.zst"

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
# Function to perform a complete cleanup of cgroup v1 resources.
precleanup() {
    log "Performing complete cleanup of cgroup v1 resources..."

    # Get a list of mounted cgroup v1 controllers
    legacy_mounts=$(mount | grep '^cgroup ' | awk '{print $3}')

    for mount_point in $legacy_mounts; do
        log "Cleaning up legacy cgroup v1 mount: $mount_point"

        # Move all processes back to root cgroup
        if [ -f "$mount_point/tasks" ]; then
            while read -r pid; do
                if [ -d "/proc/$pid" ]; then
                    echo "$pid" > /sys/fs/cgroup/tasks 2>/dev/null || true
                fi
            done < "$mount_point/tasks"
        fi

        # Unmount the cgroup v1 controller
        if ! umount "$mount_point" 2>/dev/null; then
            if ! umount -l "$mount_point" 2>/dev/null; then
                log "Warning: Could not unmount $mount_point, may require manual intervention"
            fi
        fi
    done

    # Remove any leftover cgroup v1 directories
    find /sys/fs/cgroup/* -type d -not -name 'cgroup*' -exec rmdir {} \; 2>/dev/null || true

    log "Legacy cgroup v1 controllers have been fully cleaned up"
}
# END: precleanup function

# -----------------------------------------------------------------------------
# BEGIN: setup_cgroup_v2 function
# Function to set up cgroup v2 with delegation to the current user.
setup_cgroup_v2() {
    log "Setting up cgroup v2 with delegation to $USER..."

    # Ensure cgroup v2 is mounted
    if ! mountpoint -q /sys/fs/cgroup; then
        mount -t cgroup2 none /sys/fs/cgroup || error_exit "Failed to mount cgroup v2"
    else
        if ! grep -qw cgroup2 /proc/mounts; then
            log "Remounting /sys/fs/cgroup as cgroup2"
            umount /sys/fs/cgroup
            mount -t cgroup2 none /sys/fs/cgroup || error_exit "Failed to remount cgroup v2"
        fi
    fi

    # Enable controllers in the root cgroup
    echo "+cpu +memory +io +pids" > /sys/fs/cgroup/cgroup.subtree_control

    # Create a cgroup for the user
    USER_CGROUP="/sys/fs/cgroup/$USER"
    mkdir -p "$USER_CGROUP"

    # Change ownership to the user
    chown "$USER":"$USER" "$USER_CGROUP"

    # Set appropriate permissions
    chmod 755 "$USER_CGROUP"

    # Switch to user context to enable controllers in their cgroup
    sudo -u "$USER" bash -c "echo '+cpu +memory +io +pids' > '$USER_CGROUP/cgroup.subtree_control'"

    log "cgroup v2 has been set up and delegated to user $USER"
}
# END: setup_cgroup_v2 function

# -----------------------------------------------------------------------------
# BEGIN: cleanup function
# Modified cleanup function to handle cgroup v2 cleanup.
cleanup() {
    local exit_code=$?
    log "Performing cleanup..."

    # Remove user's cgroup directory if it exists
    USER_CGROUP="/sys/fs/cgroup/$USER"
    if [ -d "$USER_CGROUP" ]; then
        sudo rmdir "$USER_CGROUP" 2>/dev/null || true
    fi

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
    rm -f "$BASE_DIR/container_$IMAGE_ID.pid"

    exit "$exit_code"
}
# END: cleanup function

# -----------------------------------------------------------------------------
# BEGIN: check_dependencies function
# Function to check required dependencies.
check_dependencies() {
    local deps=(crun sudo wget mount gpg sha256sum tar unzstd)
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "$cmd is not installed. Please install it before running this script."
        fi
    done

    # Check that crun's version is at least 1.0
    local crun_version
    crun_version=$(crun --version | head -n1 | awk '{print $3}')
    if ! printf '%s\n%s\n' "1.0" "$crun_version" | sort -V -C; then
        error_exit "crun version must be at least 1.0"
    fi
}
# END: check_dependencies function

# -----------------------------------------------------------------------------
# BEGIN: create_directories function
# Function to create necessary directories with proper permissions.
create_directories() {
    log "Creating necessary directories..."

    sudo mkdir -p "$DOWNLOAD_DIR" "$BUNDLE_DIR/rootfs" "$HOST_CONFIG_DIR" "$HOST_MEDIA_DIR"

    # Change ownership to the current user
    sudo chown -R "$(whoami):$(whoami)" "$DOWNLOAD_DIR" "$BUNDLE_DIR" "$HOST_CONFIG_DIR" "$HOST_MEDIA_DIR"

    # Set permissions
    chmod 755 "$DOWNLOAD_DIR" "$BUNDLE_DIR" "$BUNDLE_DIR/rootfs"
    chmod 755 "$HOST_CONFIG_DIR" "$HOST_MEDIA_DIR"

    # Verify directories are writable
    for dir in "$DOWNLOAD_DIR" "$BUNDLE_DIR" "$HOST_CONFIG_DIR" "$HOST_MEDIA_DIR"; do
        if [ ! -w "$dir" ]; then
            error_exit "Directory $dir is not writable. Check permissions or ownership."
        fi
    done

    log "Directories created and permissions verified."
}
# END: create_directories function

# -----------------------------------------------------------------------------
# BEGIN: download_verify_image function
# Function to download and verify the Arch Linux bootstrap image.
download_verify_image() {
    mkdir -p "$DOWNLOAD_DIR"

    log "Downloading Arch Linux bootstrap tarball..."
    wget -O "$DOWNLOAD_DIR/$IMAGE_FILE" "$IMAGE_URL_ARCH" || error_exit "Failed to download $IMAGE_URL_ARCH"

    log "Downloading signature file..."
    wget -O "$DOWNLOAD_DIR/$(basename "$IMAGE_FILE").sig" "$IMAGE_SIG_URL" || error_exit "Failed to download $IMAGE_SIG_URL"

    log "Downloading sha256sums.txt..."
    wget -O "$DOWNLOAD_DIR/sha256sums.txt" "$CHECKSUMS_URL" || error_exit "Failed to download $CHECKSUMS_URL"

    # Extract the expected SHA256 checksum from the checksum file.
    EXPECTED_CHECKSUM=$(grep "$(basename "$IMAGE_FILE")" "$DOWNLOAD_DIR/sha256sums.txt" | awk '{print $1}')
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        error_exit "Could not find expected SHA256 checksum for $IMAGE_FILE in sha256sums.txt."
    fi

    ACTUAL_CHECKSUM=$(sha256sum "$DOWNLOAD_DIR/$IMAGE_FILE" | awk '{print $1}')
    if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
        error_exit "Checksum mismatch: expected $EXPECTED_CHECKSUM but got $ACTUAL_CHECKSUM."
    fi

    log "Checksum verified successfully."

    log "Verifying the signature of the bootstrap tarball using GnuPG..."
    gpg --verify "$DOWNLOAD_DIR/$(basename "$IMAGE_FILE").sig" "$DOWNLOAD_DIR/$IMAGE_FILE" || error_exit "GPG signature verification failed."

    mkdir -p "$BUNDLE_DIR/rootfs"

    log "Extracting Arch Linux bootstrap tarball into rootfs..."
    tar --use-compress-program=unzstd -xpf "$DOWNLOAD_DIR/$IMAGE_FILE" -C "$BUNDLE_DIR/rootfs" --strip-components=1 || error_exit "Extraction failed."

    log "Arch Linux bootstrap rootfs is ready."
}
# END: download_verify_image function

# -----------------------------------------------------------------------------
# BEGIN: create_nginx_config function
# Function to create a default Nginx configuration.
create_nginx_config() {
    if [ ! -f "$HOST_NGINX_CONF" ]; then
        log "Creating default Nginx config..."
        cat < "$HOST_NGINX_CONF"
user nginx;
worker_processes auto;
error_log /var/log/nginx/error.log warn;
pid /var/run/nginx.pid;

events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;
    default_type application/octet-stream;

    log_format main '\$remote_addr - \$remote_user [\$time_local] "\$request" '
                    '\$status \$body_bytes_sent "\$http_referer" '
                    '"\$http_user_agent" "\$http_x_forwarded_for"';

    access_log /var/log/nginx/access.log main;

    sendfile on;
    keepalive_timeout 65;

    server {
        listen 80;
        server_name localhost;

        location / {
            root /usr/share/nginx/html;
            index index.html index.htm;
            autoindex on;
        }

        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-Content-Type-Options "nosniff";
        add_header X-XSS-Protection "1; mode=block";
    }
}
EOF
        sudo chmod 644 "$HOST_NGINX_CONF"
        log "Nginx config created."
    else
        log "Nginx config already exists at $HOST_NGINX_CONF."
    fi
}
# END: create_nginx_config function

# -----------------------------------------------------------------------------
# BEGIN: create_container_config function
# Function to create the container configuration (config.json).
create_container_config() {
    if [ ! -d "$BUNDLE_DIR" ]; then
        log "Error: Directory $BUNDLE_DIR does not exist."
        error_exit "Directory for config.json does not exist."
    fi

    cat < "$BUNDLE_DIR/config.json"
{
    "ociVersion": "1.0.2",
    "process": {
        "user": {"uid": 1000, "gid": 1000},
        "args": ["/usr/bin/nginx", "-g", "daemon off;"],
        "env": [
            "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            "LANG=C.UTF-8"
        ],
        "cwd": "/",
        "capabilities": {
            "bounding": ["CAP_CHOWN", "CAP_NET_BIND_SERVICE"],
            "effective": ["CAP_CHOWN", "CAP_NET_BIND_SERVICE"]
        },
        "rlimits": [{"type": "RLIMIT_NOFILE", "hard": 1024, "soft": 1024}],
        "terminal": false
    },
    "root": {"path": "rootfs", "readonly": false},
    "hostname": "arch-container",
    "linux": {
        "namespaces": [
            {"type": "pid"},
            {"type": "mount"},
            {"type": "network", "path": "/var/run/netns/$NETNS_NAME"},
            {"type": "cgroup"}
        ],
        "resources": {
            "memory": {"limit": 512000000},
            "cpu": {"weight": 1024}
        },
        "cgroupsPath": "/$USER",
        "seccomp": {
            "defaultAction": "SCMP_ACT_ERRNO",
            "architectures": ["SCMP_ARCH_X86_64"],
            "syscalls": [
                {
                    "names": [
                        "accept4", "bind", "clone", "close", "connect", "epoll_create1", "epoll_ctl", "epoll_wait",
                        "exit", "exit_group", "fstat", "futex", "getcwd", "getdents64", "getpid", "ioctl", "listen",
                        "lseek", "mkdir", "mmap", "mount", "open", "openat", "pipe2", "read", "recv", "recvfrom",
                        "rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "select", "send", "sendto",
                        "set_robust_list", "set_tid_address", "socket", "stat", "write"
                    ],
                    "action": "SCMP_ACT_ALLOW"
                }
            ]
        }
    },
    "mounts": [
        {"destination": "/proc", "type": "proc", "source": "proc"},
        {"destination": "/dev", "type": "tmpfs", "source": "tmpfs", "options": ["nosuid", "strictatime", "mode=755", "size=65536k"]},
        {"destination": "/dev/pts", "type": "devpts", "source": "devpts", "options": ["nosuid", "noexec", "newinstance", "ptmxmode=0666", "mode=0620"]},
        {"destination": "/sys", "type": "sysfs", "source": "sysfs", "options": ["nosuid", "noexec", "nodev", "ro"]},
        {"destination": "/etc/nginx/nginx.conf", "source": "$HOST_NGINX_CONF", "type": "bind", "options": ["ro", "rbind"]},
        {"destination": "/usr/share/nginx/html", "source": "$HOST_MEDIA_DIR", "type": "bind", "options": ["ro", "rbind"]}
    ]
}
EOF

    sudo chmod 644 "$BUNDLE_DIR/config.json"
    log "Container config created."
}
# END: create_container_config function

# -----------------------------------------------------------------------------
# BEGIN: setup_networking function
# Function to set up networking (network namespace and veth pair).
setup_networking() {
    log "Setting up network..."

    # Create network namespace if it doesn't exist
    if ! sudo ip netns list | grep -qw "$NETNS_NAME"; then
        log "Creating network namespace $NETNS_NAME..."
        sudo ip netns add "$NETNS_NAME"
    fi

    # Create veth pair if it doesn't exist
    if ! ip link show veth1 &>/dev/null; then
        log "Creating veth pair..."
        sudo ip link add veth0 type veth peer name veth1
        sudo ip link set veth0 netns "$NETNS_NAME"
        sudo ip link set veth1 master "$BRIDGE_NAME"
        sudo ip link set veth1 up
    fi

    sudo ip netns exec "$NETNS_NAME" ip addr add "$CONTAINER_IP" dev veth0
    sudo ip netns exec "$NETNS_NAME" ip link set veth0 up
}
# END: setup_networking function

# -----------------------------------------------------------------------------
# BEGIN: check_cgroup_version function
# Function to check and display the current cgroup version and structure.
check_cgroup_version() {
    log "Checking cgroup version..."
    if [[ -f /proc/filesystems ]] && grep -q cgroup2 /proc/filesystems; then
        log "System is using cgroup v2."
    else
        log "cgroup v2 not found; please verify your system configuration."
    fi
    log "Current cgroup structure:"
    ls -l /sys/fs/cgroup
}
# END: check_cgroup_version function

# -----------------------------------------------------------------------------
# BEGIN: start_container function
# Function to start the container.
start_container() {
    log "Starting container $IMAGE_ID..."
    sudo ip netns exec "$NETNS_NAME" crun run -b "$BUNDLE_DIR" "$IMAGE_ID" &
    local pid=$!
    echo "$pid" > "$BASE_DIR/container_$IMAGE_ID.pid"
}
# END: start_container function

# -----------------------------------------------------------------------------
# BEGIN: main function
# Main function to orchestrate the container setup.
main() {
    precleanup                 # Clean up cgroup v1 resources
    setup_cgroup_v2            # Setup cgroup v2 with user delegation
    check_dependencies          # Check for required dependencies
    create_directories          # Create necessary directories
    download_verify_image       # Download and verify the Arch Linux image
    create_nginx_config         # Create Nginx configuration
    create_container_config     # Create container configuration
    setup_networking            # Set up networking for the container
    check_cgroup_version        # Check the current cgroup version
    start_container             # Start the container

    log "Container started with port forwarding from host $HOST_PORT to container $CONTAINER_PORT."
}
# END: main function

# -----------------------------------------------------------------------------
# Invoke the main function with any provided arguments.
trap cleanup EXIT
main "$@"
