#!/bin/bash

# BPF passive security monitoring tool
# Copyright (C) 2023 Shadowpgp and @Lulz1337 /0x24
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.

# Function to display the logo
function display_logo() {
    echo """
    ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄▄▄▄▄ ▄▄▄     ▄▄   ▄▄ ▄▄▄▄▄▄▄ 
    █  ▄    █       █       █  ▄    █   █   █  █ █  █       █
    █ █▄█   █    ▄  █    ▄▄▄█ █▄█   █   █   █  █ █  █    ▄▄▄█
    █       █   █▄█ █   █▄▄▄█       █   █   █  █▄█  █   █▄▄▄ 
    █  ▄   ██    ▄▄▄█    ▄▄▄█  ▄   ██   █▄▄▄█       █    ▄▄▄█
    █ █▄█   █   █   █   █   █ █▄█   █       █       █   █▄▄▄ 
    █▄▄▄▄▄▄▄█▄▄▄█   █▄▄▄█   █▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█▄▄▄▄▄▄▄█ V2.1
    """
}

# Function to display the main menu with styling
function main_menu() {
    clear
    display_logo
    echo """
    ╔══════════════════════════════════════════════════════════════╗
    ║                  Welcome to BPFBlue V2.1                     ║
    ║              Passive Security Monitoring Tool                ║
    ║      Copyright (C) 2024 @Shadowpgp and @Lulz1337 /0x24       ║
    ╠══════════════════════════════════════════════════════════════╣
    ║ Please select an option:                                     ║
    ║                                                              ║
    ║ 1. Execve Trace                                              ║
    ║ 2. Network Trace                                             ║
    ║ 3. Network Sniffing                                          ║
    ║ 4. Open Syscall Trace                                        ║
    ║ 5. Clone Syscall Trace                                       ║
    ║ 6. Socket Syscall Trace                                      ║
    ║ 7. Bind Syscall Trace                                        ║
    ║ 8. Listen Syscall Trace                                      ║
    ║ 9. Connect Syscall Trace                                     ║
    ║ 10. Event Trace                                              ║
    ║ 11. Monitor Specific Port                                    ║
    ║ 12. Exit                                                     ║
    ║                                                              ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    read -p "Enter your choice [1-12]: " choice

    case $choice in
        1) probe="execve" ;;
        2) probe="network" ;;
        3) probe="sniff" ;;
        4) probe="open" ;;
        5) probe="clone" ;;
        6) probe="socket" ;;
        7) probe="bind" ;;
        8) probe="listen" ;;
        9) probe="connect" ;;
        10) probe="event" ;;
        11) 
            read -p "Enter the port number to monitor: " port
            probe="port"
            ;;
        12) echo "Exiting..."; exit 0 ;;
        *) echo "Invalid choice! Please select a valid option." && main_menu ;;
    esac

    execute_probe "$probe" "$port"
}

# Function to execute the selected probe
function execute_probe() {
    local probe=$1
    local port=$2

    case "$probe" in
        "execve")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_execve { printf(\"Execve syscall traced: Command - %s, Filename - %s, PID - %d\\n\", comm, str(args->filename), pid); }'"
            ;;
        "network")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_socket { printf(\"Entering Sock: Program name - %s, PID - %d\\n\", comm, pid); } tracepoint:syscalls:sys_exit_socket { printf(\"Exiting Sock: Program name - %s, PID - %d\\n\", comm, pid); }'"
            ;;
        "sniff")
            command="sudo tcpdump -vvv -i any"
            ;;
        "open")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_open { printf(\"Open syscall traced: Filename - %s, PID - %d\\n\", str(args->filename), pid); }'"
            ;;
        "clone")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_clone { printf(\"Clone syscall traced: Command - %s, PID - %d\\n\", comm, pid); }'"
            ;;
        "socket")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_socket { printf(\"Socket syscall traced: Domain - %d, PID - %d\\n\", args->domain, pid); }'"
            ;;
        "bind")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_bind { printf(\"Bind syscall traced: Socket - %s, PID - %d\\n\", comm, pid); }'"
            ;;
        "listen")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_listen { printf(\"Listen syscall traced: Socket - %s, PID - %d\\n\", comm, pid); }'"
            ;;
        "connect")
            command="sudo bpftrace -e 'tracepoint:syscalls:sys_enter_connect { printf(\"Connect syscall traced: Socket - %s, PID - %d\\n\", comm, pid); }'"
            ;;
        "event")
            command="sudo bpftrace -e 'tracepoint:sched:sched_switch { printf(\"Event: %s %s\\n\", args->prev_comm, args->next_comm); }'"
            ;;
        "port")
            command="sudo tcpdump -i any port $port -vv"
            ;;
        *)
            echo "Invalid probe selected."
            exit 1
            ;;
    esac

    echo "Executing probe: $probe"
    echo "Running command: $command"
    eval "$command"
}

# Start the script by displaying the main menu
main_menu
