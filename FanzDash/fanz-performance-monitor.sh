#!/usr/bin/env bash
# FANZ Advanced Performance Monitor
# Real-time performance monitoring and health checks for all FANZ services

set -euo pipefail

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

# Configuration
REFRESH_INTERVAL=2
LOG_DIR="/tmp/fanz-logs"

# Service configuration
SERVICES=(
    "FanzDash:5174:Main Dashboard & Control Center"
    "FanzSSO:5175:Single Sign-On Authentication"
    "FanzMoneyDash:5176:Financial Management System"
    "PupFanz:5177:PupFanz Creator Platform"
    "BoyFanz:5178:BoyFanz Creator Platform"
)

# Get system info
get_system_metrics() {
    local cpu_usage=$(top -l 1 -s 0 | grep "CPU usage" | awk '{print $3}' | cut -d'%' -f1 2>/dev/null || echo "0")
    local memory_pressure=$(memory_pressure 2>/dev/null | grep "System-wide memory free percentage" | awk '{print $4}' | cut -d'%' -f1 2>/dev/null || echo "50")
    local load_avg=$(uptime | awk -F'load averages:' '{print $2}' | awk '{print $1}' | cut -d',' -f1 2>/dev/null || echo "0.5")
    
    echo "$cpu_usage:$memory_pressure:$load_avg"
}

# Get service metrics
get_service_metrics() {
    local port=$1
    local response_time="N/A"
    local status_code="N/A"
    local memory_mb="N/A"
    local cpu_percent="N/A"
    
    # Check if service is running
    if lsof -i :$port >/dev/null 2>&1; then
        local pid=$(lsof -t -i:$port 2>/dev/null | head -1)
        
        # Get response time
        local start_time=$(date +%s%3N)
        if curl -s --connect-timeout 1 --max-time 2 "http://localhost:$port/health" >/dev/null 2>&1; then
            local end_time=$(date +%s%3N)
            response_time=$((end_time - start_time))
            status_code="200"
        else
            # Try root endpoint
            if curl -s --connect-timeout 1 --max-time 2 "http://localhost:$port/" >/dev/null 2>&1; then
                local end_time=$(date +%s%3N)
                response_time=$((end_time - start_time))
                status_code="200"
            else
                status_code="ERR"
            fi
        fi
        
        # Get process metrics
        if [[ -n "$pid" ]]; then
            local ps_output=$(ps -p $pid -o rss=,pcpu= 2>/dev/null || echo "0 0.0")
            memory_mb=$(echo $ps_output | awk '{printf "%.1f", $1/1024}')
            cpu_percent=$(echo $ps_output | awk '{print $2}')
        fi
    fi
    
    echo "$response_time:$status_code:$memory_mb:$cpu_percent"
}

# Display header
show_header() {
    clear
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║                    ${WHITE}FANZ ECOSYSTEM PERFORMANCE MONITOR${CYAN}                    ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════════════╝${NC}"
    echo
}

# Display system overview
show_system_overview() {
    local metrics=$(get_system_metrics)
    local cpu=$(echo $metrics | cut -d':' -f1)
    local memory=$(echo $metrics | cut -d':' -f2)
    local load=$(echo $metrics | cut -d':' -f3)
    
    echo -e "${BLUE}📊 SYSTEM OVERVIEW${NC}"
    echo -e "────────────────────────────────────────────────────────────────────────────"
    printf "%-20s %-15s %-15s %-15s %-15s\n" "Metric" "Current" "Status" "Threshold" "Health"
    echo -e "────────────────────────────────────────────────────────────────────────────"
    
    # CPU Usage
    local cpu_status="${GREEN}GOOD${NC}"
    if (( $(echo "$cpu > 70" | bc -l 2>/dev/null || echo 0) )); then
        cpu_status="${YELLOW}HIGH${NC}"
    fi
    if (( $(echo "$cpu > 90" | bc -l 2>/dev/null || echo 0) )); then
        cpu_status="${RED}CRITICAL${NC}"
    fi
    printf "%-20s %-15s %-15s %-15s %-15s\n" "CPU Usage" "${cpu}%" "$cpu_status" "< 80%" "✓"
    
    # Memory
    local mem_status="${GREEN}GOOD${NC}"
    if (( $(echo "$memory < 20" | bc -l 2>/dev/null || echo 0) )); then
        mem_status="${YELLOW}LOW${NC}"
    fi
    if (( $(echo "$memory < 10" | bc -l 2>/dev/null || echo 0) )); then
        mem_status="${RED}CRITICAL${NC}"
    fi
    printf "%-20s %-15s %-15s %-15s %-15s\n" "Memory Free" "${memory}%" "$mem_status" "> 15%" "✓"
    
    # Load Average
    local load_status="${GREEN}GOOD${NC}"
    if (( $(echo "$load > 2.0" | bc -l 2>/dev/null || echo 0) )); then
        load_status="${YELLOW}HIGH${NC}"
    fi
    if (( $(echo "$load > 5.0" | bc -l 2>/dev/null || echo 0) )); then
        load_status="${RED}CRITICAL${NC}"
    fi
    printf "%-20s %-15s %-15s %-15s %-15s\n" "Load Average" "$load" "$load_status" "< 3.0" "✓"
    
    echo
}

# Display service metrics
show_service_metrics() {
    echo -e "${PURPLE}🚀 SERVICE PERFORMANCE${NC}"
    echo -e "────────────────────────────────────────────────────────────────────────────"
    printf "%-15s %-6s %-12s %-10s %-10s %-8s %-20s\n" "Service" "Port" "Response" "Status" "Memory" "CPU%" "Description"
    echo -e "────────────────────────────────────────────────────────────────────────────"
    
    for service_info in "${SERVICES[@]}"; do
        IFS=':' read -r name port description <<< "$service_info"
        local metrics=$(get_service_metrics $port)
        IFS=':' read -r response_time status_code memory_mb cpu_percent <<< "$metrics"
        
        # Format response time
        local response_display="N/A"
        if [[ "$response_time" != "N/A" ]]; then
            response_display="${response_time}ms"
        fi
        
        # Status color
        local status_color="${RED}DOWN${NC}"
        if [[ "$status_code" == "200" ]]; then
            status_color="${GREEN}UP${NC}"
        elif [[ "$status_code" == "ERR" ]]; then
            status_color="${YELLOW}ERR${NC}"
        fi
        
        # Memory display
        local memory_display="N/A"
        if [[ "$memory_mb" != "N/A" ]]; then
            memory_display="${memory_mb}MB"
        fi
        
        # CPU display
        local cpu_display="N/A"
        if [[ "$cpu_percent" != "N/A" ]]; then
            cpu_display="${cpu_percent}%"
        fi
        
        printf "%-15s %-6s %-12s %-10s %-10s %-8s %-20s\n" \
            "$name" "$port" "$response_display" "$status_color" "$memory_display" "$cpu_display" "$(echo $description | cut -c1-18)"
    done
    
    echo
}

# Show recent logs
show_recent_activity() {
    echo -e "${YELLOW}📋 RECENT ACTIVITY${NC}"
    echo -e "────────────────────────────────────────────────────────────────────────────"
    
    local log_files=("$LOG_DIR"/*.log)
    local activity_count=0
    
    for log_file in "${log_files[@]}"; do
        if [[ -f "$log_file" ]]; then
            local service_name=$(basename "$log_file" .log | tr '[:lower:]' '[:upper:]')
            local recent_lines=$(tail -2 "$log_file" 2>/dev/null | grep -v "^$" | tail -1)
            
            if [[ -n "$recent_lines" ]]; then
                echo -e "${CYAN}$service_name:${NC} $(echo "$recent_lines" | cut -c1-60)"
                ((activity_count++))
            fi
        fi
    done
    
    if [[ $activity_count -eq 0 ]]; then
        echo -e "${CYAN}No recent activity in logs${NC}"
    fi
    
    echo
}

# Show network connections
show_network_status() {
    echo -e "${GREEN}🌐 NETWORK STATUS${NC}"
    echo -e "────────────────────────────────────────────────────────────────────────────"
    
    local total_connections=$(lsof -i -P | grep LISTEN | grep -E "(517[4-8])" | wc -l | tr -d ' ')
    local active_ports=$(lsof -i -P | grep LISTEN | grep -E "(517[4-8])" | awk '{print $9}' | cut -d':' -f2 | sort -n | tr '\n' ' ')
    
    echo -e "Active FANZ Ports: ${WHITE}$total_connections${NC} ports listening"
    echo -e "Port Range: ${WHITE}$active_ports${NC}"
    
    # Check external connectivity
    local internet_status="${RED}OFFLINE${NC}"
    if ping -c 1 -W 1000 8.8.8.8 >/dev/null 2>&1; then
        internet_status="${GREEN}ONLINE${NC}"
    fi
    echo -e "Internet: $internet_status"
    
    echo
}

# Main monitoring loop
run_monitor() {
    while true; do
        show_header
        show_system_overview
        show_service_metrics
        show_recent_activity
        show_network_status
        
        echo -e "${CYAN}Press Ctrl+C to exit | Refreshing every ${REFRESH_INTERVAL}s${NC}"
        echo -e "${CYAN}Last updated: $(date)${NC}"
        
        sleep $REFRESH_INTERVAL
    done
}

# Handle cleanup
cleanup() {
    echo -e "\n${CYAN}Performance monitoring stopped.${NC}"
    exit 0
}

trap cleanup INT TERM

# Check if bc is available (for calculations)
if ! command -v bc >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: 'bc' command not found. Some calculations may be simplified.${NC}"
    echo
fi

# Start monitoring
echo -e "${GREEN}Starting FANZ Performance Monitor...${NC}"
sleep 1
run_monitor