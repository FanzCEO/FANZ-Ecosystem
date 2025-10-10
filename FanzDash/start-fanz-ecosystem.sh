#!/usr/bin/env bash
# FANZ Ecosystem Startup Script
# Starts all FANZ services in the correct order with proper coordination

set -euo pipefail

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Configuration
FANZ_BASE_DIR="/Users/joshuastone/Development/FANZ"
LOG_DIR="/tmp/fanz-logs"
STARTUP_DELAY=3

# Ensure log directory exists
mkdir -p "$LOG_DIR"

log() {
    echo -e "${BLUE}[FANZ-STARTUP]${NC} $1"
}

warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

info() {
    echo -e "${CYAN}[INFO]${NC} $1"
}

# Check if a port is available
check_port_available() {
    local port=$1
    if ! lsof -i :$port >/dev/null 2>&1; then
        return 0  # Port is available
    else
        return 1  # Port is in use
    fi
}

# Wait for a service to be ready
wait_for_service() {
    local service_name=$1
    local port=$2
    local max_attempts=30
    local attempt=1
    
    info "Waiting for $service_name to be ready on port $port..."
    
    while [[ $attempt -le $max_attempts ]]; do
        if curl -s -f "http://localhost:$port/health" >/dev/null 2>&1; then
            success "$service_name is ready!"
            return 0
        fi
        
        if [[ $((attempt % 5)) -eq 0 ]]; then
            info "Still waiting for $service_name... (attempt $attempt/$max_attempts)"
        fi
        
        sleep 2
        ((attempt++))
    done
    
    warn "$service_name may not be fully ready, continuing anyway..."
    return 1
}

# Start a service
start_service() {
    local service_name=$1
    local port=$2
    local directory=$3
    local command=$4
    local log_file="$LOG_DIR/$(echo $service_name | tr '[:upper:]' '[:lower:]').log"
    
    log "Starting $service_name..."
    
    # Check if directory exists
    if [[ ! -d "$directory" ]]; then
        error "Directory not found: $directory"
        return 1
    fi
    
    # Check if port is available
    if ! check_port_available $port; then
        warn "Port $port is already in use. Attempting to free it..."
        local pid=$(lsof -t -i:$port 2>/dev/null || echo "")
        if [[ -n "$pid" ]]; then
            kill -TERM $pid 2>/dev/null || true
            sleep 2
        fi
    fi
    
    # Change to service directory
    cd "$directory"
    
    # Set environment variables
    export PORT=$port
    export NODE_ENV=development
    export FANZ_SERVICE=$service_name
    export FANZ_LOG_LEVEL=info
    
    # Copy development environment if it exists
    if [[ -f "$FANZ_BASE_DIR/FanzDash/.env.development" ]]; then
        cp "$FANZ_BASE_DIR/FanzDash/.env.development" .env.development 2>/dev/null || true
    fi
    
    # Start the service
    info "Starting $service_name in $directory on port $port"
    nohup $command > "$log_file" 2>&1 &
    local pid=$!
    
    # Save PID for later management
    echo $pid > "$LOG_DIR/$(echo $service_name | tr '[:upper:]' '[:lower:]').pid"
    
    # Wait a moment and check if it started
    sleep $STARTUP_DELAY
    
    if ps -p $pid >/dev/null 2>&1; then
        success "$service_name started successfully (PID: $pid)"
        info "Logs: tail -f $log_file"
        return 0
    else
        error "Failed to start $service_name"
        error "Check logs: cat $log_file"
        return 1
    fi
}

# Check prerequisites
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if Node.js is available
    if ! command -v node >/dev/null 2>&1; then
        error "Node.js is not installed or not in PATH"
        exit 1
    fi
    
    # Check if npm is available
    if ! command -v npm >/dev/null 2>&1; then
        error "npm is not installed or not in PATH"
        exit 1
    fi
    
    success "Prerequisites check passed"
}

# Install dependencies if needed
install_dependencies() {
    local directory=$1
    local service_name=$2
    
    if [[ ! -d "$directory/node_modules" ]] || [[ "$directory/package.json" -nt "$directory/node_modules" ]]; then
        log "Installing dependencies for $service_name..."
        cd "$directory"
        npm install --legacy-peer-deps 2>/dev/null || npm install || {
            warn "Failed to install dependencies for $service_name, continuing anyway..."
        }
    fi
}

# Main startup sequence
startup_fanz_ecosystem() {
    echo -e "\n${CYAN}🚀 STARTING FANZ ECOSYSTEM 🚀${NC}\n"
    
    check_prerequisites
    
    # Service startup order (dependencies first)
    log "Starting FANZ services in dependency order..."
    
    # 1. FanzSSO (Authentication service - needed by others)
    if [[ -d "$FANZ_BASE_DIR/FanzSSO" ]]; then
        install_dependencies "$FANZ_BASE_DIR/FanzSSO" "FanzSSO"
        start_service "FanzSSO" 5175 "$FANZ_BASE_DIR/FanzSSO" "npm start"
    else
        warn "FanzSSO directory not found, skipping..."
    fi
    
    # 2. FanzDash (Main dashboard - core service)
    if [[ -d "$FANZ_BASE_DIR/FanzDash" ]]; then
        install_dependencies "$FANZ_BASE_DIR/FanzDash" "FanzDash"
        start_service "FanzDash" 5174 "$FANZ_BASE_DIR/FanzDash" "npm run dev"
    else
        error "FanzDash directory not found!"
        exit 1
    fi
    
    # 3. FanzMoneyDash (Financial management)
    if [[ -d "$FANZ_BASE_DIR/FanzMoneyDash" ]]; then
        install_dependencies "$FANZ_BASE_DIR/FanzMoneyDash" "FanzMoneyDash"
        start_service "FanzMoneyDash" 5176 "$FANZ_BASE_DIR/FanzMoneyDash" "npm run dev"
    else
        warn "FanzMoneyDash directory not found, skipping..."
    fi
    
    # 4. PupFanz (Platform service)
    if [[ -d "$FANZ_BASE_DIR/PupFanz" ]]; then
        install_dependencies "$FANZ_BASE_DIR/PupFanz" "PupFanz"
        start_service "PupFanz" 5177 "$FANZ_BASE_DIR/PupFanz" "npm run dev"
    else
        warn "PupFanz directory not found, skipping..."
    fi
    
    # 5. BoyFanz (Platform service)
    if [[ -d "$FANZ_BASE_DIR/BoyFanz" ]]; then
        install_dependencies "$FANZ_BASE_DIR/BoyFanz" "BoyFanz"
        start_service "BoyFanz" 5178 "$FANZ_BASE_DIR/BoyFanz" "npm start"
    else
        warn "BoyFanz directory not found, skipping..."
    fi
    
    echo -e "\n${GREEN}✅ FANZ ECOSYSTEM STARTUP COMPLETE${NC}\n"
    
    # Show summary
    show_startup_summary
}

# Show startup summary
show_startup_summary() {
    echo -e "${PURPLE}=== FANZ ECOSYSTEM SUMMARY ===${NC}"
    
    local services=(
        "FanzSSO:5175"
        "FanzDash:5174" 
        "FanzMoneyDash:5176"
        "PupFanz:5177"
        "BoyFanz:5178"
    )
    
    for service_port in "${services[@]}"; do
        IFS=':' read -r name port <<< "$service_port"
        local pid_file="$LOG_DIR/$(echo $name | tr '[:upper:]' '[:lower:]').pid"
        
        if [[ -f "$pid_file" ]]; then
            local pid=$(cat "$pid_file")
            if ps -p $pid >/dev/null 2>&1; then
                echo -e "  ${GREEN}✓${NC} $name: http://localhost:$port (PID: $pid)"
            else
                echo -e "  ${RED}✗${NC} $name: Failed to start"
            fi
        else
            echo -e "  ${YELLOW}?${NC} $name: Not started"
        fi
    done
    
    echo -e "\n${CYAN}Useful Commands:${NC}"
    echo -e "  Monitor all logs: ${YELLOW}tail -f $LOG_DIR/*.log${NC}"
    echo -e "  Check status:     ${YELLOW}./fanz-ecosystem-status.sh status${NC}"
    echo -e "  Stop all:         ${YELLOW}./fanz-ecosystem-status.sh stop${NC}"
    
    echo -e "\n${BLUE}Main Dashboard:${NC} http://localhost:5174"
    echo -e "${BLUE}Authentication:${NC} http://localhost:5175"
    echo -e "${BLUE}Financial:${NC}      http://localhost:5176"
    echo -e "\n${GREEN}FANZ Ecosystem is ready! 🎉${NC}"
}

# Handle script termination
cleanup() {
    log "Cleaning up startup script..."
    exit 0
}

trap cleanup INT TERM

# Run the startup
startup_fanz_ecosystem