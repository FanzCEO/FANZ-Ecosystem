#!/usr/bin/env bash
# FANZ Command Center Dashboard
# Interactive management interface for the entire FANZ ecosystem

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m' # No Color

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LOG_DIR="/tmp/fanz-logs"

# Create log directory if it doesn't exist
mkdir -p "$LOG_DIR"

# Clear screen and show header
show_header() {
    clear
    echo -e "${CYAN}"
    echo "████████╗ █████╗ ███╗   ██╗███████╗"
    echo "██╔════╝██╔══██╗████╗  ██║╚══███╔╝"  
    echo "█████╗  ███████║██╔██╗ ██║  ███╔╝ "
    echo "██╔══╝  ██╔══██║██║╚██╗██║ ███╔╝  "
    echo "██║     ██║  ██║██║ ╚████║███████╗"
    echo "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═══╝╚══════╝"
    echo -e "${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════${NC}"
    echo -e "${PURPLE}            FANZ ECOSYSTEM COMMAND CENTER${NC}"
    echo -e "${WHITE}════════════════════════════════════════════════════════${NC}"
    echo
}

# Show current status
show_status() {
    echo -e "${BLUE}🚀 ECOSYSTEM STATUS${NC}"
    echo "────────────────────────────────────────────────────────"
    
    local services=(
        "FanzDash:5174:Main Dashboard & Control Center"
        "FanzSSO:5175:Single Sign-On Authentication"
        "FanzMoneyDash:5176:Financial Management System"
        "PupFanz:5177:PupFanz Creator Platform"
        "BoyFanz:5178:BoyFanz Creator Platform"
    )
    
    for service_info in "${services[@]}"; do
        IFS=':' read -r name port description <<< "$service_info"
        
        if lsof -i :$port >/dev/null 2>&1; then
            local pid=$(lsof -t -i:$port 2>/dev/null | head -1)
            echo -e "  ${GREEN}●${NC} ${WHITE}$name${NC} - $description"
            echo -e "    ${CYAN}http://localhost:$port${NC} (PID: $pid)"
        else
            echo -e "  ${RED}●${NC} ${WHITE}$name${NC} - $description"
            echo -e "    ${YELLOW}Not running${NC} (Port $port available)"
        fi
        echo
    done
}

# Show logs
show_logs() {
    echo -e "${BLUE}📋 SERVICE LOGS${NC}"
    echo "────────────────────────────────────────────────────────"
    
    local log_files=("$LOG_DIR"/*.log)
    if [[ ${#log_files[@]} -eq 0 ]]; then
        echo -e "${YELLOW}No log files found${NC}"
        return
    fi
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            local service_name=$(basename "$log_file" .log)
            echo -e "${CYAN}=== ${service_name^^} LOGS ===${NC}"
            tail -5 "$log_file" 2>/dev/null || echo "No recent logs"
            echo
        fi
    done
}

# Show system information
show_system_info() {
    echo -e "${BLUE}💻 SYSTEM INFORMATION${NC}"
    echo "────────────────────────────────────────────────────────"
    echo -e "  ${WHITE}Hostname:${NC}     $(hostname)"
    echo -e "  ${WHITE}OS:${NC}           $(uname -s) $(uname -r)"
    echo -e "  ${WHITE}Architecture:${NC} $(uname -m)"
    echo -e "  ${WHITE}Node.js:${NC}      $(node --version 2>/dev/null || echo 'Not installed')"
    echo -e "  ${WHITE}npm:${NC}          $(npm --version 2>/dev/null || echo 'Not installed')"
    echo -e "  ${WHITE}Current User:${NC} $(whoami)"
    echo -e "  ${WHITE}Working Dir:${NC}  $(pwd)"
    echo
    
    local memory_info=$(ps -A -o pid,ppid,rss,comm | grep -E "(node|npm)" | grep -v grep | wc -l)
    echo -e "  ${WHITE}FANZ Node Processes:${NC} $memory_info"
    
    local port_count=$(lsof -i -P | grep LISTEN | grep -E "(517[4-8]|300[0-2])" | wc -l)
    echo -e "  ${WHITE}FANZ Ports Active:${NC}   $port_count"
    echo
}

# Show quick actions menu
show_menu() {
    echo -e "${BLUE}🎛️  QUICK ACTIONS${NC}"
    echo "────────────────────────────────────────────────────────"
    echo -e "  ${GREEN}[1]${NC} Start All Services"
    echo -e "  ${RED}[2]${NC} Stop All Services" 
    echo -e "  ${YELLOW}[3]${NC} Restart All Services"
    echo -e "  ${CYAN}[4]${NC} Check Service Status"
    echo -e "  ${PURPLE}[5]${NC} View Live Logs"
    echo -e "  ${BLUE}[6]${NC} Open Service URLs"
    echo -e "  ${WHITE}[7]${NC} System Information"
    echo -e "  ${GREEN}[8]${NC} Update Dependencies"
    echo -e "  ${RED}[9]${NC} Emergency Stop All"
    echo -e "  ${YELLOW}[0]${NC} Exit Command Center"
    echo "────────────────────────────────────────────────────────"
}

# Execute action
execute_action() {
    local choice=$1
    
    case $choice in
        1)
            echo -e "${GREEN}Starting all FANZ services...${NC}"
            "$SCRIPT_DIR/start-fanz-ecosystem.sh" 2>/dev/null || {
                echo -e "${RED}Failed to start some services. Check logs for details.${NC}"
            }
            press_enter
            ;;
        2)
            echo -e "${RED}Stopping all FANZ services...${NC}"
            "$SCRIPT_DIR/fanz-ecosystem-status.sh" stop
            press_enter
            ;;
        3)
            echo -e "${YELLOW}Restarting all FANZ services...${NC}"
            "$SCRIPT_DIR/fanz-ecosystem-status.sh" restart
            press_enter
            ;;
        4)
            echo -e "${CYAN}Checking service status...${NC}"
            "$SCRIPT_DIR/fanz-ecosystem-status.sh" status
            press_enter
            ;;
        5)
            echo -e "${PURPLE}Opening live logs (Press Ctrl+C to exit)...${NC}"
            echo -e "${CYAN}Available logs:${NC}"
            ls -la "$LOG_DIR"/*.log 2>/dev/null || echo "No logs found"
            echo
            read -p "Enter log file name (without path/extension) or 'all' for all logs: " log_choice
            if [[ "$log_choice" == "all" ]]; then
                tail -f "$LOG_DIR"/*.log
            else
                tail -f "$LOG_DIR/$log_choice.log" 2>/dev/null || echo "Log file not found"
            fi
            press_enter
            ;;
        6)
            echo -e "${BLUE}Opening service URLs in browser...${NC}"
            local urls=(
                "http://localhost:5174"
                "http://localhost:5175" 
                "http://localhost:5176"
                "http://localhost:5177"
                "http://localhost:5178"
            )
            
            for url in "${urls[@]}"; do
                echo -e "${CYAN}Opening: $url${NC}"
                open "$url" 2>/dev/null || {
                    echo -e "${YELLOW}Could not open $url automatically${NC}"
                    echo "Please open manually: $url"
                }
            done
            press_enter
            ;;
        7)
            show_system_info
            press_enter
            ;;
        8)
            echo -e "${GREEN}Updating dependencies...${NC}"
            local dirs=(
                "/Users/joshuastone/Development/FANZ/FanzDash"
                "/Users/joshuastone/Development/FANZ/FanzSSO"
                "/Users/joshuastone/Development/FANZ/FanzMoneyDash"
                "/Users/joshuastone/Development/FANZ/PupFanz"
            )
            
            for dir in "${dirs[@]}"; do
                if [[ -d "$dir" ]]; then
                    echo -e "${CYAN}Updating $(basename "$dir")...${NC}"
                    cd "$dir"
                    npm update --legacy-peer-deps 2>/dev/null || npm update || {
                        echo -e "${YELLOW}Warning: Could not update $(basename "$dir")${NC}"
                    }
                fi
            done
            press_enter
            ;;
        9)
            echo -e "${RED}EMERGENCY STOP - Killing all FANZ processes...${NC}"
            pkill -f "Development/FANZ" || true
            pkill -f "FANZ-Core-Platforms" || true
            echo -e "${GREEN}All processes stopped${NC}"
            press_enter
            ;;
        0)
            echo -e "${CYAN}Exiting FANZ Command Center...${NC}"
            exit 0
            ;;
        *)
            echo -e "${RED}Invalid choice. Please try again.${NC}"
            sleep 1
            ;;
    esac
}

# Wait for user input
press_enter() {
    echo
    read -p "Press Enter to continue..."
}

# Main loop
main() {
    while true; do
        show_header
        show_status
        show_menu
        
        echo -n "Enter your choice [0-9]: "
        read -r choice
        
        execute_action "$choice"
    done
}

# Handle script termination
cleanup() {
    echo -e "\n${CYAN}Command Center shutting down...${NC}"
    exit 0
}

trap cleanup INT TERM

# Run the command center
main