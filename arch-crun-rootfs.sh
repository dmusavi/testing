#End of variable
#!/bin/bash

# Set strict error handling
set -euo pipefail  # Exit immediately on error, treat unset variables as errors, and ensure correct handling of pipes
IFS=$'\n\t'  # Set Internal Field Separator for handling newlines and tabs

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
HOST_CONFIG_DIR="$BASE_DIR" # Directory for Nginx configuration on the host
HOST_NGINX_CONF="$HOST_CONFIG_DIR/nginx.conf"  # Path to Nginx configuration on the host
HOST_MEDIA_DIR="$HOST_CONFIG_DIR/media"  # Directory for media files to be served by Nginx on the host

# URLs for the bootstrap tarball, its signature, and the checksum file
IMAGE_URL_ARCH="https://geo.mirror.pkgbuild.com/iso/2025.02.01/archlinux-bootstrap-2025.02.01-x86_64.tar.zst"
IMAGE_SIG_URL="https://geo.mirror.pkgbuild.com/iso/2025.02.01/archlinux-bootstrap-2025.02.01-x86_64.tar.zst.sig"
CHECKSUMS_URL="https://archlinux.org/iso/2025.02.01/sha256sums.txt"

# The tarball filename
IMAGE_FILE="archlinux-bootstrap-2025.02.01-x86_64.tar.zst"

# Directories for downloads and bundle extraction
DOWNLOAD_DIR="$BASE_DIR/downloads"
BUNDLE_DIR="$BASE_DIR"

# Setup logging
log() {
    echo -e "[INFO] $1" | logger -s -t "$(basename "$0")"  # Log informational messages with system logger
}
error_exit() {
    echo -e "[ERROR] $1"  # Log error messages
    cleanup  # Call cleanup function
    exit 1  # Exit with a non-zero status
}

# Log the start of the script
log "Script started"
#End of setup logging
# Cleanup function
cleanup() {
    local exit_code=$?  # Capture the exit code
    log "Performing cleanup..."

    # Stop and remove container
    if sudo crun list | grep -qw "$IMAGE_ID"; then
        sudo crun stop "$IMAGE_ID" 2>/dev/null || true  # Stop the container
        sudo crun delete -f "$IMAGE_ID" 2>/dev/null || true  # Force delete the container
    fi

    # Clean up network namespace and interfaces
    if sudo ip netns list | grep -qw "$NETNS_NAME"; then
        sudo ip netns del "$NETNS_NAME" 2>/dev/null || true  # Delete network namespace
    fi

    # Remove veth pair if created by this script
    if ip link show veth1 &>/dev/null; then
        sudo ip link delete veth1 2>/dev/null || true  # Delete veth pair
    fi

    # Remove temporary directories
    sudo rm -rf "$DOWNLOAD_DIR" "$BUNDLE_DIR"

    # Remove the PID file
    rm -f "/tmp/container_$IMAGE_ID.pid"

    exit "$exit_code"  # Exit with the captured exit code
}
#End of cleanup function 
# Set up trap for cleanup
trap cleanup ERR EXIT  # Catch ERR and EXIT signals to execute cleanup function

# Function to check dependencies
check_dependencies() {
    local deps=(crun sudo wget mount)  # Using wget as per the script, mount is included for cgroup operations
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "$cmd is not installed. Please install it before running this script."  # Check if all dependencies are installed
        fi
    done

    # Check crun version
    local crun_version
    crun_version=$(crun --version | head -n1 | awk '{print $3}')  # Get crun version
    if ! printf '%s\n%s\n' "1.0" "$crun_version" | sort -V -C; then  # Check if crun version is at least 1.0
        error_exit "crun version must be at least 1.0"  # Exit if version is not valid
    fi
}
#End of trap
# Function to create necessary directories with proper permissions
create_directories() {
    log "Creating necessary directories..."

    # Create directories
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
# End of Function to create necessary directories with proper permissions
# Function to download and verify image
download_verify_image() {
    # Ensure the download directory exists
    mkdir -p "$DOWNLOAD_DIR"

    # Download the Arch Linux bootstrap tarball
    log "Downloading Arch Linux bootstrap tarball..."
    wget -O "$DOWNLOAD_DIR/$IMAGE_FILE" "$IMAGE_URL_ARCH" || error_exit "Failed to download $IMAGE_URL_ARCH"

    # Download the signature file
    log "Downloading signature file..."
    wget -O "$DOWNLOAD_DIR/$(basename "$IMAGE_FILE").sig" "$IMAGE_SIG_URL" || error_exit "Failed to download $IMAGE_SIG_URL"

    # Download the checksum file
    log "Downloading sha256sums.txt..."
    wget -O "$DOWNLOAD_DIR/sha256sums.txt" "$CHECKSUMS_URL" || error_exit "Failed to download $CHECKSUMS_URL"

    # Extract the expected SHA256 checksum from the checksum file.
    # The expected checksum is assumed to be the first field on the line containing the tarball's filename.
    EXPECTED_CHECKSUM=$(grep "$(basename "$IMAGE_FILE")" "$DOWNLOAD_DIR/sha256sums.txt" | awk '{print $1}')
    if [ -z "$EXPECTED_CHECKSUM" ]; then
        error_exit "Could not find expected SHA256 checksum for $IMAGE_FILE in sha256sums.txt."
    fi

    # Calculate the actual SHA256 checksum of the downloaded tarball
    ACTUAL_CHECKSUM=$(sha256sum "$DOWNLOAD_DIR/$IMAGE_FILE" | awk '{print $1}')
    if [ "$EXPECTED_CHECKSUM" != "$ACTUAL_CHECKSUM" ]; then
        error_exit "Checksum mismatch: expected $EXPECTED_CHECKSUM but got $ACTUAL_CHECKSUM."
    fi

    log "Checksum verified successfully."

    # Verify the signature using GnuPG (keys are assumed already imported)
    log "Verifying the signature of the bootstrap tarball using GnuPG..."
    gpg --verify "$DOWNLOAD_DIR/$(basename "$IMAGE_FILE").sig" "$DOWNLOAD_DIR/$IMAGE_FILE" || error_exit "GPG signature verification failed."

    # Create the bundle's rootfs directory (where the tarball will be extracted)
    mkdir -p "$BUNDLE_DIR/rootfs"

    # Extract the tarball into the container's rootfs directory using unzstd for Zstandard compression
    log "Extracting Arch Linux bootstrap tarball into rootfs..."
    tar --use-compress-program=unzstd -xpf "$DOWNLOAD_DIR/$IMAGE_FILE" -C "$BUNDLE_DIR/rootfs" --strip-components=1 || error_exit "Extraction failed."

    log "Arch Linux bootstrap rootfs is ready."
}
# End of the Function to download and verify image
# Function to check dependencies
check_dependencies() {
    local deps=(crun sudo wget mount)  # Using wget as per the script, mount is included for cgroup operations
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "$cmd is not installed. Please install it before running this script."  # Check if all dependencies are installed
        fi
    done

    # Check crun version
    local crun_version
    crun_version=$(crun --version | head -n1 | awk '{print $3}')  # Get crun version
    if ! printf '%s\n%s\n' "1.0" "$crun_version" | sort -V -C; then  # Check if crun version is at least 1.0
        error_exit "crun version must be at least 1.0"  # Exit if version is not valid
    fi
}


#End of download and create function
# Function to create Nginx config
create_nginx_config() {
    if [ ! -f "$HOST_NGINX_CONF" ]; then  # Check if the Nginx config file does not exist
        log "Creating default Nginx config..."
        cat <<EOF > "$HOST_NGINX_CONF"
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
            autoindex on;  # Enable directory listing for serving static media
        }

        # Security headers
        add_header X-Frame-Options "SAMEORIGIN";
        add_header X-Content-Type-Options "nosniff";
        add_header X-XSS-Protection "1; mode=block";
    }
}
EOF
        sudo chmod 644 "$HOST_NGINX_CONF"  # Set permissions for Nginx config file
        log "Nginx config created."
    else
        log "Nginx config already exists at $HOST_NGINX_CONF."
    fi
}
#End of crete nginx config function
# Function to create container config
# Function to create container config
create_container_config() {
    if [ ! -d "$BUNDLE_DIR" ]; then
        log "Error: Directory $BUNDLE_DIR does not exist."
        error_exit "Directory for config.json does not exist."
    fi

    cat <<EOF > "$BUNDLE_DIR/config.json"
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
        "cgroupsPath": "/sys/fs/cgroup",
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
#End of create container config function
#End of create container config function
#Function to create namesapces networking
setup_networking() {
    log "Setting up network..."

    # Create network namespace if it doesn't exist
    if ! sudo ip netns list | grep -qw "$NETNS_NAME"; then
        log "Creating network namespace $NETNS_NAME..."
        sudo ip netns add "$NETNS_NAME"
    fi

    # Create veth pair if they don't exist
    if ! ip link show veth1 &>/dev/null; then
        log "Creating veth pair..."
        sudo ip link add veth0 type veth peer name veth1
        sudo ip link set veth0 netns "$NETNS_NAME"
        sudo ip link set veth1 master "$BRIDGE_NAME"
        sudo ip link set veth1 up  # Bring up the host side of veth pair
    fi
    
    sudo ip netns exec "$NETNS_NAME" ip addr add "$CONTAINER_IP" dev veth0  # Assign IP to container's veth interface
    sudo ip netns exec "$NETNS_NAME" ip link set veth0 up  # Bring up container's veth interface
}
#End of the function to create namesapces networking
# Function to check dependencies
check_dependencies() {
    local deps=(crun sudo wget mount)  # Added mount to the list of dependencies
    for cmd in "${deps[@]}"; do
        if ! command -v "$cmd" >/dev/null 2>&1; then
            error_exit "$cmd is not installed. Please install it before running this script."  # Check if all dependencies are installed
        fi
    done

    # Check crun version
    local crun_version
    crun_version=$(crun --version | head -n1 | awk '{print $3}')  # Get crun version
    if ! printf '%s\n%s\n' "1.0" "$crun_version" | sort -V -C; then  # Check if crun version is at least 1.0
        error_exit "crun version must be at least 1.0"  # Exit if version is not valid
    fi
}

# Function to check cgroup version
check_cgroup_version() {
    log "Checking cgroup version..."
    if [[ -f /proc/cgroups ]]; then
        if grep -q '1' /proc/cgroups; then
            log "System is using cgroup v1."
        else
            log "System appears to be using cgroup v2."
        fi
    else
        log "Unable to determine cgroup version from /proc/cgroups. Assuming cgroup v2."
    fi
    log "Current cgroup structure:"
    ls -l /sys/fs/cgroup
}

# Function to prepare cgroup v2 environment
prepare_cgroup_v2() {
    log "Preparing cgroup v2 environment..."
    if ! mount | grep -q "/sys/fs/cgroup cgroup2"; then
        log "Mounting unified cgroup2 filesystem..."
        if sudo mount -t cgroup2 none /sys/fs/cgroup; then
            log "Successfully mounted cgroup2."
            # Set correct permissions for cgroup2 directory
            sudo chmod 755 /sys/fs/cgroup
            # Ensure root has ownership
            sudo chown root:root /sys/fs/cgroup
            # Optionally, you might want to set specific permissions for subdirectories
            sudo find /sys/fs/cgroup -type d -exec sudo chmod 755 {} \;
            log "Permissions set for cgroup2."
        else
            error_exit "Failed to mount cgroup2. Check if cgroup2 support is enabled in your kernel."
        fi
    else
        log "cgroup2 is already mounted."
        # Check and set permissions if they are not correct
        if [ "$(stat -c %a /sys/fs/cgroup)" != "755" ] || [ "$(stat -c %U:%G /sys/fs/cgroup)" != "root:root" ]; then
            sudo chmod 755 /sys/fs/cgroup
            sudo chown root:root /sys/fs/cgroup
            sudo find /sys/fs/cgroup -type d -exec sudo chmod 755 {} \;
            log "Permissions adjusted for existing cgroup2 mount."
        else
            log "Permissions for cgroup2 are already correct."
        fi
    fi
    log "Cgroup v2 preparation completed."
}

# Function to verify cgroup setup
verify_cgroup() {
    log "Verifying cgroup setup..."
    ls -l /sys/fs/cgroup
    log "Verification completed."
}
# End of Function to verify cgroup setup
# Function to start the container
start_container() {
    log "Starting container $IMAGE_ID..."
    sudo ip netns exec "$NETNS_NAME" crun run -b "$BUNDLE_DIR" "$IMAGE_ID" &
    local pid=$!
    echo "$pid" > "$BASE_DIR/container_$IMAGE_ID.pid"  # Write the PID to a file
}
# End of Function to start the container
# Main function
main() {
    check_dependencies      # Check for required dependencies
    create_directories      # Create necessary directories
    download_verify_image   # Download and verify the Arch Linux image
    create_nginx_config     # Create Nginx configuration
    create_container_config # Create container configuration
    setup_networking        # Set up networking for the container
    check_cgroup_version    # Check cgroup version
    prepare_cgroup_v2       # Prepare cgroup v2 environment
    verify_cgroup           # Verify cgroup setup
    start_container         # Start the container

    log "Container started with port forwarding from host $HOST_PORT to container $CONTAINER_PORT."
}

# Invoke the main function
main "$@"
