import subprocess
import ipaddress
import os.path

title = "NMAP SCRIPT"
# --------------------- NMAP ENUMERATION ----------------------
# This python3 script uses built-in nmap scans, intensity types
# and file output options to scan networks and enumerate specific
# hosts on the network. Some user-input is validated.
#
#
# email:

# define ANSI color schemes.
black = "\033[0;30m"
red = "\033[0;31m"
green = "\033[0;32m"
yellow = "\033[0;33m"
blue = "\033[0;34m"
white = "\033[0;37m"
bright_green = "\033[0;92m"


# ----------------------- FUNCTIONS ------------------------------------

def check_directory():
    if os.path.exists("/usr/bin/nmap"):
        print("/usr/bin/nmap located.")
    else:
        subprocess.run(["sudo", "apt-get", "install", "nmap"])
    print()


def host_discovery():
    """Calls nmap's ping sweeping scan"""
    subprocess.run(["nmap", "-T5", "-sn", network_address + cidr])


def nmapscan_domain_1():
    subprocess.run(["nmap", port, intensity, scan_option_1, "-vv", domain])


def nmapscan_domain_2():
    subprocess.run(["nmap", port, intensity, scan_option_1, scan_option_2,
                    "-vv", domain])


def nmapscan_domain_3():
    subprocess.run(["nmap", port, intensity, scan_option_1, scan_option_2,
                    scan_option_3, "-vv", domain])


def nmapscan_1():
    subprocess.run(["nmap", port, intensity, scan_option_1, "-vv", target])


def nmapscan_2():
    subprocess.run(["nmap", port, intensity, scan_option_1, scan_option_2,
                    "-vv", target])


def nmapscan_3():
    subprocess.run(["nmap", port, intensity, scan_option_1, scan_option_2,
                    scan_option_3, "-vv", target])


# ----------------------- VARIABLES ------------------------------------

directory = "/usr/bin/nmap"


intensity_types = ["-T0", "-T1", "-T2", "-T3", "-T4", "-T5"]


scan_types = ['{0}-sT {1}= TCP Connect'.format(yellow, white),
              '{0}-sS {1}= SYN Stealth'.format(yellow, white),
              '{0}-sU {1}= UDP port'.format(yellow, white),
              '{0}-O {1}= OS Detection'.format(yellow, white),
              '{0}-sV {1}= Version Detection'.format(yellow, white),
              '{0}-sN {1}= Null'.format(yellow, white),
              '{0}-sF {1}= FIN'.format(yellow, white),
              '{0}-sA {1}= ACK'.format(yellow, white),
              '{0}-sX {1}= XMAS'.format(yellow, white)]


scan_options = ['-sT', '-sS', '-sU', '-O', '-sV', '-sN', '-sF', '-sA', '-sX']

nse_options = ['http-title']

intensity_options = ['{0} -T0 {1}= Paranoid (Intrusion Detection System '
                     'evasion)'.format(yellow, white),
                     '{0} -T1 {1}= Sneaky (Intrusion Detection System '
                     'evasion)'.format(yellow, white),
                     '{0} -T2 {1}= Polite (less bandwidth and target system '
                     'resources)'.format(yellow, white),
                     '{0} -T3 {1}= Normal (default speed)'.format(yellow, white),
                     '{0} -T4 {1}= Aggressive (Assumes you are on a reasonably f'
                     'ast and reliable '
                     'network)'.format(yellow, white),
                     '{0} -T5 {1}= Insane (Assumes you are on an extraordinarily '
                     'fast network)'.format(yellow, white)]

port_options = ['Scan a SINGLE PORT (e.g., {0}-p 22 {1}or {2}-p 80{3})'.format(yellow,
                                                                               white,
                                                                               yellow,
                                                                               white),
                'Scan a RANGE OF PORTS (e.g., {0}-p 1-100{1})'.format(yellow, white),
                'Scan 100 MOST COMMON PORTS (e.g., {0}-F{1})'.format(yellow, white),
                'Scan UDP PORTS (e.g., {0}-pU:213{1})'.format(yellow, white)]


# --------------------------- START ------------------------------------
# Prints title to screen.
print(green + title.center(60))
print()

# Verifies /usr/bin/nmap exists; otherwise, install.
check_directory()

# DOMAIN ENUMERATION
# User is asked if they would like to scan a domain name.
domain_answer = input("{0}Are you scanning a domain name?: ".format(white))
if domain_answer.lower() == 'y':
    print()
    domain = input("Enter the {0}domain: ".format(red))
    print()

    # User is prompted with available intensity levels.
    print('{0}Intensity Levels:'.format(white))
    for elem in intensity_options:
        print(white + elem)
    print()

    # User selects an intensity level.
    intensity = input("{0}Select an {1}intensity {2}type: ".format(white, yellow,
                                                                   white))

    # The code below validates user selected a correct intensity level.
    while True:
        if intensity not in intensity_types:
            intensity = input("{0}Select an {1}intensity {2}type: ".format(white,
                                                                           yellow,
                                                                           white))
        else:
            break

    # User prompted with port probing instructions.
    print()
    print('Port Probing Options:')
    print()
    for elem in port_options:
        print(elem)
    print()
    print("{0}NOTE: {1}Ports must be entered following the {2}syntax {3}above"
          .format(red, white, yellow, white))
    print()

    # User selects ports to probe on domain, if applicable.
    port = input('{0}which ports would you like to probe? (Press "Enter" to skip): '
                 .format(white))
    if port == '':
        print()
        print("{0}scan will default to the 1,000 most popular ports.".format(yellow))
        print()
    else:
        print()

    # User is displayed a list of available nmap scan options to choose from.
    for elem in scan_types:  # Select an nmap scan type.
        print(elem)
    print()

    # User selects scan_option_1 for scanning domain.
    scan_option_1 = input("Select a {0}scan {1}option from above: ".format(green,
                                                                           white))
    while True:  # nmap scan validation
        if scan_option_1 not in scan_options:
            scan_option_1 = input("Select a {0}scan {1}option from above: "
                                  .format(green, white))
        else:
            break

    # User is asked if he/she would like to stack a second nmap scan.
    answer = input("Would you like to stack a second scan option? [y/n]: ")
    if answer.lower() == 'n':
        print()
        print("Initiating " + green + scan_option_1 + white + " scan on " + red +
              domain + white)
        print()
        nmapscan_domain_1()  # If no, domain is scanned with one scan option.
        exit()

    # If yes to a 2nd scan option, user specifies scan_option_2 for domain.
    elif answer.lower() == 'y':
        print("{0}Note: Please choose only one of -sA, -sT, -sN, -sS, and "
              "-sX".format(yellow))
        print()
        scan_option_2 = input("{0}which scan?: ".format(white))
        if scan_option_2 in scan_options:
            print()
            print(green + scan_option_2 + white + " added.")
            print()
        while scan_option_2 not in scan_options:  # validation
            scan_option_2 = input("{0}That's not a scan option. Try again: "
                                  .format(white))
            if scan_option_2 in scan_options:
                break

    # User is asked if he/she would like to stack a third scan.
    answer_2 = input("{0}Would you like to stack an third scan option? [y/n]: "
                     .format(white))
    if answer_2.lower() == 'n':
        print()
        print(f"{white}Initiating {green}{scan_option_1} {scan_option_2}{white}"
              f" scan on {red}{domain}{white}")
        print()
        nmapscan_domain_2()  # If no, domain is scanned with two scan options.

    # If yes to a third scan option, user specifies scan_option_3 for domain.
    elif answer.lower() == 'y':
        print("{0}Note: Please choose only one of -sA, -sT, -sN, -sS, and -sX"
              .format(yellow))
        print()
        scan_option_3 = input("{0}which scan?: ".format(white))
        if scan_option_3 in scan_options:
            print()
            print(f"{white}initiating {green}{scan_option_1} {scan_option_2} "
                  f"{scan_option_3}{white} scan on {red}{domain}{white}")
            print()
            nmapscan_domain_3()  # if yes, domain is scanned with 3 scan options.
            exit()
        while scan_option_3 not in scan_options:  # validation
            scan_option_3 = input("{0}That's not a scan option. Try again: "
                                  .format(white))
            if scan_option_3 in scan_options:
                print()
                print(white + "initiating " + green + scan_option_1 + " " +
                      scan_option_2 + " " + scan_option_3 + white +
                      " scan on " + red + domain + white)
                print()
                nmapscan_domain_3()

# if user selects "no," they will be directed to input a host address.
elif domain_answer.lower() == 'n':
    print()

# NETWORK ENUMERATION
# User specifies network address.
while True:  # IP address validation.
    network_address = input("{0}Enter network address: ".format(white))
    try:
        print(ipaddress.ip_address(network_address))
        print()
        print("{0}valid IP address".format(green))
        print()
        break
    except:
        print()
        print("{0}IP not Valid".format(red))
        print()
    finally:
        if network_address == "q":
            print("Script Finished")
            exit()

# user specifies subnet mask in CIDR notation.
cidr = input(white + 'Enter the subnet mask for '
             + network_address +
             ', such as "/8," "/16," or "/24": ')

# Calls host_discovery to ping sweep network to discover available hosts.
# on the network.
print()
print(green + "Ping sweeping " + network_address + cidr)
print()
host_discovery()
print()

# User selects a target from the available hosts.
while True:  # IP address validation.
    target = input("{0}Choose a {1}target {2}to enumerate from the list above: "
                   .format(white, red, white))
    try:
        print(ipaddress.ip_address(target))
        print()
        print("{0}Valid IP address".format(green))
        print()
        break
    except:
        print()
        print("{0}IP not Valid".format(red))
        print()
    finally:
        if target == "q":
            print("Script Finished")
            exit()
print()

# User is displayed all available intensity levels to choose from.
print("{0}Intensity Levels:".format(white))
for elem in intensity_options:
    print(white + elem)
print()

# user selects intensity level.
intensity = input("{0}Select an {1}intensity {2}type: ".format(white, yellow,
                                                               white))

# The code below validates that a correct intensity level was selected.
while True:
    if intensity not in intensity_types:
        intensity = input("{0}Select an {1}intensity {2}type: ".format(white,
                                                                       yellow,
                                                                       white))
    else:
        break
print()

# User is prompted with port probing instructions.
print()
print('Port Probing Options:')
print()
for elem in port_options:
    print(elem)
print()
print("{0}NOTE: {1}Ports must be entered following the {2}syntax {3}above"
      .format(red, white, yellow, white))
print()

# User is asked which ports they would like to probe.
port = input('{0}Which ports would you like to probe? (Press "Enter" to skip): '
             .format(white))
if port == '':
    print()
    print("{0}scan will default to the 1,000 most popular ports.".format(yellow))
    print()
else:
    print()

# Displays the available nmap scan options to choose from.
for elem in scan_types:  # Select an nmap scan type.
    print(elem)
    print()

# User selects scan_option_1 for target.
scan_option_1 = input("Select a {0}scan option {1}from above: ".format
                      (green, white))
while True:  # nmap scan validation
    if scan_option_1 not in scan_options:
        scan_option_1 = input("Select a {0}scan option {1}from above: "
                              .format(green, white))
    else:
        break
print()

# User is asked if he/she wants to stack a second scan option.
answer = input("Would you like to stack a second scan option? [y/n]: ")
if answer.lower() == 'n':
    print()
    print("Initiating " + green + scan_option_1 + white + " scan on " +
          red + target + white)
    print()
    nmapscan_1()  # if no, target is scanned with one scan option.
    exit()

# If yes, user specifies scan_option_2 for target.
elif answer.lower() == 'y':
    print("{0}Note: Please choose only one of -sA, -sT, -sN, -sS, and -sX"
          .format(yellow))
    print()
    scan_option_2 = input("{0}which scan?: ".format(white))
    if scan_option_2 in scan_options:
        print()
        print(green + scan_option_2 + white + " added.")
        print()
    while scan_option_2 not in scan_options:  # validation
        scan_option_2 = input("{0}That's not a scan option. Try again: "
                              .format(white))
        if scan_option_2 in scan_options:
            break

#  User is asked if he/she wants to stack a third scan option.
answer_2 = input("{0}Would you like to stack an third scan option? [y/n]: "
                 .format(white))
if answer_2.lower() == 'n':
    print()
    print(white + "Initiating " + green + scan_option_1 + " " +
          scan_option_2 + white + " scan on " + red + target + white)
    print()
    nmapscan_2()  # If no, target is scanned with two scan options.

# If yes, user specifies scan_option_3
elif answer.lower() == 'y':
    print("{0}Note: Please choose only one of -sA, -sT, -sN, -sS, and -sX"
          .format(yellow))
    print()
    scan_option_3 = input("{0}which scan?: ".format(white))
    if scan_option_3 in scan_options:
        print()
        print(white + "initiating " + green + scan_option_1 + " " +
              scan_option_2 + " " + scan_option_3 + white + " scan on "
              + red + target + white)
        print()
        nmapscan_3()  # if yes, target is scanned with 3 scan options.
        exit()
    while scan_option_3 not in scan_options:  # validation
        scan_option_3 = input("{0}That's not a scan option. Try again: ".format(white))
        if scan_option_3 in scan_options:
            print()
            print(white + "initiating " + green + scan_option_1 + " " +
                  scan_option_2 + " " + scan_option_3 + white +
                  " scan on " + red + target + white)
            print()
            nmapscan_3()
exit()
