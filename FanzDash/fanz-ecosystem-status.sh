#!/usr/bin/env bash
# FANZ Ecosystem Status Checker and Service Coordinator
# Monitors all FANZ platform services and resolves port conflicts

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
SERVICES=(
    "FanzDash:5174:/Users/joshuastone/Development/FANZ/FanzDash:npm run dev"
    "FanzSSO:5175:/Users/joshuastone/Development/FANZ/FanzSSO:npm start"
    "FanzMoneyDash:5176:/Users/joshuastone/Development/FANZ/FanzMoneyDash:npm run dev"
    "PupFanz:5177:/Users/joshuastone/Development/FANZ/PupFanz:npm start"
    "BoyFanz:5178:/Users/joshuastone/Development/FANZ/BoyFanz:npm start"
)

log() {
    echo -e "${BLUE}[FANZ]${NC} $1"
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

# Check if a port is in use
check_port() {
    local port=$1
    if lsof -i :$port >/dev/null 2>&1; then
        return 0  # Port is in use
    else
        return 1  # Port is free
    fi
}

# Get process using a port
get_port_process() {
    local port=$1
    lsof -i :$port | tail -n +2 | head -1 | awk '{print $2 " " $1}' 2>/dev/null || echo "unknown unknown"
}

# Stop a process by PID
stop_process() {
    local pid=$1
    local name=$2
    if kill -TERM $pid 2>/dev/null; then
        info "Stopped $name (PID: $pid)"
        sleep 2
        if ps -p $pid >/dev/null 2>&1; then
            warn "Force killing $name (PID: $pid)"
            kill -KILL $pid 2>/dev/null || true
        fi
    fi
}

# Check FANZ service status
check_service_status() {
    local service_name=$1
    local port=$2
    local directory=$3
    local command=$4
    
    echo -e "\n${PURPLE}=== $service_name Status ===${NC}"
    
    # Check if directory exists
    if [[ ! -d "$directory" ]]; then
        error "Directory not found: $directory"
        return 1
    fi
    
    # Check if port is in use
    if check_port $port; then
        local process_info=$(get_port_process $port)
        local pid=$(echo $process_info | cut -d' ' -f1)
        local proc_name=$(echo $process_info | cut -d' ' -f2)
        success "$service_name is running on port $port (PID: $pid, Process: $proc_name)"
        
        # Check if it's the right service
        if [[ $proc_name == "node" ]] || [[ $proc_name == "npm" ]]; then
            success "✓ Service appears to be running correctly"
        else
            warn "! Port $port is occupied by unexpected process: $proc_name"
        fi
    else
        warn "$service_name is not running on port $port"
    fi
    
    # Check package.json exists
    if [[ -f "$directory/package.json" ]]; then
        success "✓ package.json found"
        local scripts=$(cat "$directory/package.json" | grep -A 10 '"scripts"' | head -15 || true)
        if [[ -n "$scripts" ]]; then
            info "Available scripts:"
            echo "$scripts" | grep -E '(dev|start|build)' | sed 's/^/    /' || true
        fi
    else
        error "✗ package.json not found"
    fi
}

# Start a FANZ service
start_service() {
    local service_name=$1
    local port=$2
    local directory=$3
    local command=$4
    
    log "Starting $service_name..."
    
    if [[ ! -d "$directory" ]]; then
        error "Directory not found: $directory"
        return 1
    fi
    
    # Check if port is already in use
    if check_port $port; then
        local process_info=$(get_port_process $port)
        local pid=$(echo $process_info | cut -d' ' -f1)
        warn "Port $port is already in use by PID $pid. Stopping existing process..."
        stop_process $pid "$service_name-existing"
        sleep 2
    fi
    
    # Change to service directory and start
    cd "$directory"
    
    # Set environment variables
    export PORT=$port
    export NODE_ENV=development
    export FANZ_SERVICE=$service_name
    
    log "Starting $service_name in $directory on port $port"
    nohup $command > "/tmp/$(echo $service_name | tr '[:upper:]' '[:lower:]').log" 2>&1 &
    local new_pid=$!
    
    # Wait a moment and check if it started
    sleep 3
    if ps -p $new_pid >/dev/null 2>&1; then
        success "$service_name started successfully (PID: $new_pid)"
        info "Logs: tail -f /tmp/$(echo $service_name | tr '[:upper:]' '[:lower:]').log"
    else
        error "Failed to start $service_name"
        error "Check logs: cat /tmp/$(echo $service_name | tr '[:upper:]' '[:lower:]').log"
    fi
}

# Stop all FANZ services
stop_all_services() {
    log "Stopping all FANZ services..."
    
    for service in "${SERVICES[@]}"; do
        IFS=':' read -r name port directory command <<< "$service"
        if check_port $port; then
            local process_info=$(get_port_process $port)
            local pid=$(echo $process_info | cut -d' ' -f1)
            stop_process $pid "$name"
        fi
    done
    
    # Also stop any node processes in FANZ directories
    ps aux | grep -E "Development/FANZ|Documents/FANZ" | grep -E "(node|npm)" | grep -v grep | while read line; do
        local pid=$(echo $line | awk '{print $2}')
        local cmd=$(echo $line | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; printf "\n"}')
        warn "Stopping FANZ-related process: $pid - $cmd"
        kill -TERM $pid 2>/dev/null || true
    done
    
    sleep 2
    success "All FANZ services stopped"
}

# Start all FANZ services
start_all_services() {
    log "Starting all FANZ services..."
    
    for service in "${SERVICES[@]}"; do
        IFS=':' read -r name port directory command <<< "$service"
        start_service "$name" "$port" "$directory" "$command"
        sleep 2  # Stagger starts
    done
}

# Check overall ecosystem health
check_ecosystem() {
    echo -e "\n${CYAN}🚀 FANZ ECOSYSTEM STATUS 🚀${NC}\n"
    
    log "Checking FANZ base directory: $FANZ_BASE_DIR"
    if [[ -d "$FANZ_BASE_DIR" ]]; then
        success "✓ FANZ base directory found"
        info "Contents: $(ls -1 "$FANZ_BASE_DIR" | tr '\n' ' ')"
    else
        error "✗ FANZ base directory not found"
    fi
    
    echo -e "\n${PURPLE}=== Service Status Overview ===${NC}"
    for service in "${SERVICES[@]}"; do
        IFS=':' read -r name port directory command <<< "$service"
        check_service_status "$name" "$port" "$directory" "$command"
    done
    
    echo -e "\n${PURPLE}=== Port Usage Summary ===${NC}"
    info "Checking common FANZ ports..."
    for port in 5174 5175 5176 5177 5178 3000 3001 3002; do
        if check_port $port; then
            local process_info=$(get_port_process $port)
            echo -e "  Port $port: ${GREEN}OCCUPIED${NC} by $process_info"
        else
            echo -e "  Port $port: ${YELLOW}FREE${NC}"
        fi
    done
    
    echo -e "\n${PURPLE}=== Node.js Processes ===${NC}"
    local node_processes=$(ps aux | grep -E "(node|npm)" | grep -v grep | grep -E "(Development/FANZ|Documents/FANZ)" | wc -l)
    info "Found $node_processes FANZ-related Node.js processes"
    
    if [[ $node_processes -gt 0 ]]; then
        ps aux | grep -E "(node|npm)" | grep -v grep | grep -E "(Development/FANZ|Documents/FANZ)" | while read line; do
            local pid=$(echo $line | awk '{print $2}')
            local cmd=$(echo $line | awk '{for(i=11;i<=NF;i++) printf "%s ", $i; printf "\n"}' | cut -c1-80)
            echo -e "  PID $pid: $cmd"
        done
    fi
}

# Show help
show_help() {
    echo -e "\n${CYAN}FANZ Ecosystem Manager${NC}"
    echo -e "Usage: $0 [command]"
    echo -e "\nCommands:"
    echo -e "  ${GREEN}status${NC}      - Check status of all FANZ services"
    echo -e "  ${GREEN}start${NC}       - Start all FANZ services"
    echo -e "  ${GREEN}stop${NC}        - Stop all FANZ services"
    echo -e "  ${GREEN}restart${NC}     - Restart all FANZ services"
    echo -e "  ${GREEN}health${NC}      - Perform ecosystem health check"
    echo -e "  ${GREEN}ports${NC}       - Show port usage"
    echo -e "  ${GREEN}logs${NC}        - Show recent logs"
    echo -e "  ${GREEN}help${NC}        - Show this help"
    echo -e "\nExample: $0 status"
}

# Show logs
show_logs() {
    log "Recent FANZ service logs:"
    for log_file in /tmp/fanzdash.log /tmp/fanzsso.log /tmp/fanzmoneydash.log /tmp/pupfanz.log /tmp/boyfanz.log; do
        if [[ -f "$log_file" ]]; then
            echo -e "\n${PURPLE}=== $(basename $log_file) ===${NC}"
            tail -20 "$log_file" || true
        fi
    done
}

# Main script logic
case "${1:-status}" in
    "status")
        check_ecosystem
        ;;
    "start")
        start_all_services
        ;;
    "stop")
        stop_all_services
        ;;
    "restart")
        stop_all_services
        sleep 3
        start_all_services
        ;;
    "health")
        check_ecosystem
        ;;
    "ports")
        echo -e "\n${PURPLE}=== Port Usage ===${NC}"
        lsof -i -P | grep LISTEN | sort -k 9 || true
        ;;
    "logs")
        show_logs
        ;;
    "help"|"--help"|"-h")
        show_help
        ;;
    *)
        error "Unknown command: $1"
        show_help
        exit 1
        ;;
esac