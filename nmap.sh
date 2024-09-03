#!/bin/bash
# Beautiful colors for output
RED='\033[0;31m'
YELLOW='\033[0;33m'
GREEN='\033[0;32m'
NC='\033[0m'

# Print help 
help() {
printf "
Usage: ./nmap.sh [OPTION]...
Scan the network for open ports/services/operating systems/common CVEs. If HTTP sites are located on any port, scan for directories/common CVEs.

Run with sudo to grant permissions for SYN/Stealth scans.

Syntax: sudo ./nmap.sh -n 192.168.0.0/24 -i eth0 -c 3.0 -w 7kTi-sdfsdfa -a 7432893074:AAFHStvfsdjlkfsdsvTz3dsIDvET833RH8 -c 13279872 -l 172.16.0.2:9600

  -h, --help            display this help and exit;
  -n, --network         specify host or network to scan; 
  -i, --interface       specify source network interface;
  -m, --mincvss         specify minimum CVSS score to display for vulscan nmap;
  -w, --wp-token        specify WPScan token for scanning sites based on WordPress;
  -a, --api-token-tg    specify token for Telegram API to send scan reports;
  -c, --chat-id-tg      specify Telegram chat ID to send scan reports;
  -l, --logstash-url    specify the Logstash host to which the logs should be sent.
"
exit 0
}


# Validate command-line options
validate() {
    options=("network" "interface")
    for option in "${options[@]}"; do 
        if [ -z "${!option}" ]; then 
            printf "./nmap.sh: need to define -- '--${option}'\n"
            printf "Try './nmap.sh --help' for more information.${NC}\n"
            exit 1
        fi 
    done 
}

packages=("python3" "curl" "nmap" "nikto" "git" "dirb" "docker-ce" "docker-ce-cli" "containerd.io" "docker-buildx-plugin" "docker-compose-plugin" "wdiff")


# Check and install required packages
install_if_not_exists() {
    if dpkg -s "$1" &>/dev/null; then
        PKG_EXIST=$(dpkg -s "$1" |
                      grep "install ok installed")
        if [ -n "$PKG_EXIST" ]; then
            printf "${GREEN}===== ${1} Already Installed =====${NC}\n"
            return
        fi
    fi

    printf "${YELLOW}===== Installing ${1} =====${NC}\n"

    if echo "${1}" | grep -q docker; then
        apt-get update
        apt-get install -y ca-certificates curl
        install -m 0755 -d /etc/apt/keyrings
        curl -fsSL https://download.docker.com/linux/ubuntu/gpg -o /etc/apt/keyrings/docker.asc
        chmod a+r /etc/apt/keyrings/docker.asc
        echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | tee /etc/apt/sources.list.d/docker.list > /dev/null
        apt-get update
        apt-get install -y docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
        printf "${GREEN}===== ${1} Successfully Installed =====${NC}\n"
        return
    elif apt install -y "${1}"; then
        printf "${GREEN}===== ${1} Successfully Installed =====${NC}\n"
        return
    fi

    printf "${RED}===== Something Went Wrong With ${1} =====${NC}\n"
}

rotate_reports() {
    printf "${YELLOW}===== Rotating Reports =====${NC}\n"
    cd ../
    if [[ $(ls -l  | wc -l) -gt 8 ]]; then
        report=$(cd ../ | stat -c '%W %n' * | sort -k1n | head -n 1 | awk '{ print $2 }')
        rm -rf $report
        printf "${GREEN}===== Deleted ${report} =====${NC}\n"
    fi
    cd -
}

# Check for and install nmap-vulners script
install_nmap_vulners() {
    if [ -d ./nmap-vulners ]; then
        printf "${GREEN}===== nmap-vulners exists, continuing...=====${NC}\n"
    else
        printf "${YELLOW}===== Cloning Git Repository nmap-vulners =====${NC}\n"
        if git clone https://github.com/vulnersCom/nmap-vulners; then
            printf "${GREEN}===== Success =====${NC}\n"
        else
            printf "${RED}===== Something Went Wrong =====${NC}\n"
        fi
    fi
}

# Check for and install nmapos script
install_nmapos() {
    if [ -f ./nmap_logstash.py ]; then
        printf "${GREEN}===== nmap_logstash exists, continuing...=====${NC}\n"
    else
        printf "${YELLOW}===== Cloning nmap_logstash.py =====${NC}\n"
        if curl -q  https://raw.githubusercontent.com/Millen93/nmapos/main/nmap_logstash.py -o sosi &> /dev/null ; then
            printf "${GREEN}===== Success =====${NC}\n"
        else
            printf "${RED}===== Something Went Wrong =====${NC}\n"
        fi
    fi
}

# Export reports to Logstash
# This not ready yet https://github.com/Millen93/nmapos.git
export_to_logstash() {
    reports=( "active_hosts" "active_ports" "active_services" "vulners" )
    
    python3 ./nmap_logstash.py --url 

    for report in "{reports[@]}"; do 
        python3 ./nmap_logstash.py --host CHANGEME --port CHANGEME $report 
    done
} 

# Scan for active hosts
active_hosts_check() {
    local hosts=()
    for active_host in $(nmap -sn "$1" -oX "./active_hosts.xml" -oG -| grep -oE '[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3}' | tail -n+2);
    do
        hosts+=("$active_host")
    done
    echo "${hosts[@]}" > diff/net_hosts
    echo "${hosts[@]}"
}

# Start web scanners
dirb_scan() {
  printf "${YELLOW}===== Dirb Scan ${1} =====${NC}\n"
  dirb $1 -o "dirb/${2}:${3}.txt" > /dev/null
}

nikto_scan() {
  printf "${YELLOW}===== Nikto Scan ${1} =====${NC}\n"
  nikto -h ${1} -o "nikto/${2}:${3}.txt" > /dev/null 2> /dev/null
}

wp_scan() {
  printf "${YELLOW}===== Wordpress Scan ${1} =====${NC}\n"
  docker network create -o parent=$4 macvlan_net > /dev/null 2> /dev/null
  docker run  --network macvlan_net  --rm wpscanteam/wpscan --url $1 --api-token $5 > wp_scan/${2}:${3}.txt
}

# Scan for active ports/service/cve on hosts
active_ports_scan() {
    local act_hosts=("$@")
    local http=()
    for active_host in "${act_hosts[@]}"; do
        printf "${YELLOW}===== Searching For Ports In ${active_host} =====${NC}\n"
        ports=$(nmap -Pn -p- -sS "$active_host" -oX "active_ports_output/${active_host}.xml" -oG - | grep -oE '[0-9]{1,6}/' | sed 's/.$//; s/ /,/g' | tr '\n' ',' | rev | cut -c2- | rev)

        echo ${ports} > diff/${active_host}

        # Scan for service on ports
          #Define all the working http services oh host
        printf "${YELLOW}===== Searching For Services In ${active_host} =====${NC}\n"
        http=($(nmap -Pn -p-$ports -sV --version-intensity 1 -A "$active_host" -oX "service_version/${active_host}.xml" -oG - | grep -oE '(\w+/+)+\w+?\|?http(/+\w+)' | grep -oE '[0-9]{1,6}'  ))

        # Scan for vulnerabilities
        printf "${YELLOW}===== Searching For CVEs In ${active_host} =====${NC}\n"
        nmap -sV -A -p-$ports --script=../../nmap-vulners/vulners.nse --script-args mincvss="$mincvss" "$active_host" -oX "vulnerability_scan/${active_host}.xml" > /dev/null


        for port in $http; do

          if $(curl https://$active_host:${port} -I --insecure 2> /dev/null ); then
            protocol="https"
          else
            protocol="http"
          fi

          dirb_scan $protocol://${active_host}:${port}  ${active_host} ${port}
          nikto_scan "$protocol://${active_host}:${port}" ${active_host} ${port}

          wp_url=$(cat dirb/${active_host}:${port}.txt | grep -Eo "https?://([0-9]{0,3}\.){3}[0-9]{0,3}:([0-9]{1,5})?/.*wp" | grep -Eo "https?://([0-9]{0,3}\.){3}[0-9]{0,3}:([0-9]{1,5})?/\w*" | head -n 1)

          if [[ $wp_url == "" ]]; then
            printf "${YELLOW}===== No Wordpress Found =====${NC}\n"
          else
             if [[ -v $wp_token ]]; then wp_scan ${wp_url} ${active_host} ${port} ${interface} ${wp_token}; fi
          fi


        done

        wait
    done
}

differ_check() {

  cd diff

  for i in $(ls -la | grep -oE "([0-9]{1,3}\.){3}[0-9]{1,3}"); do
    echo -e "$i OPEN PORTS $(cat $i)\n" >> tg_notification
  done

  cd -

  cd ../
  previous_report=$(stat -c '%W %n' * | sort -k1n | tail -n 2 | head -n 1 | awk '{ print $2 }')
  cd -

  MESSAGE="
  📡 *Отчет о сканировании сети*
  📅 Дата: ${dir}

  **Подробности сканирования:**
  - Сканируемая подсеть: ${network}
  - Инструменты: nmap, wpscan, nikto, dirb

  **Список сетевых узлов:**
  \`\`\`
  $(cat diff/net_hosts)
  \`\`\`

  **Список доступных портов:**
  \`\`\`
  $(cat diff/tg_notification)
  \`\`\`
  "

  host_diff=$(wdiff -3 diff/net_hosts ../${previous_report}/diff/net_hosts)
  if [ -n "$host_diff" ]; then
    MESSAGE="
    ${MESSAGE}
    🔄 **Изменения в сетевых узлах с момента предыдущего сканирования (${previous_report}):**
    \`\`\`
    ${host_diff}
    \`\`\`
    "
  fi

  port_diff=$(diff -y diff/tg_notification ../${previous_report}/diff/tg_notification)
  if [ -n "$port_diff" ]; then
    MESSAGE="
    ${MESSAGE}
    🔄 **Изменения в портах с момента предыдущего сканирования (${previous_report}):**
    \`\`\`
    ${port_diff}
    \`\`\`
    "
  fi

  curl -s -X POST https://api.telegram.org/bot${API_TOKEN_TG}/sendMessage -d parse_mode=markdown -d chat_id=${CHAT_ID_TG} -d text="$MESSAGE" > /dev/null

}


# Print warn
printf "\033[7;37mFOR ENTERTAINMENT PURPOSES ONLY, DEVELOPERS NOT RESPONSIBLE FOR USER ACTIONS${NC}\n\n"

# Get command-line options
while [[ $# -gt 0 ]]; do 
    case "$1" in 
      --verbose|-v)
      set -x 
      ;;
      --help|-h)
      help
      ;; 
      --network|-n)
      shift 
      network=$1
      ;;
      --mincvss|-c)
      shift 
      mincvss=$1
      ;;
      --interface|-i)
      shift 
      interface=$1
      ;;
      --wp-token|-w)
      shift 
      wp_token=$1
      ;;
      --api-token-tg|-a)
      shift 
      API_TOKEN_TG=$1
      ;; 
      --chat-id-tg|-c)
      shift 
      CHAT_ID_TG=$1
      ;;
      --logstash-url|-l)
      shift 
      LOGSTASH=$1
      ;;
      *)
      printf "./nmap.sh: invalid option -- '${1}'\n"
      printf "Try './nmap.sh --help' for more information.\n"
      exit 1
      ;;
    esac
    shift 
done

validate

# Validate sudo
if [[ $(id --user) != 0 ]]; then
    printf "Run ./nmap.sh with sudo to grant permissions for SYN/Stealth scans.\n"
    printf "Try './nmap.sh --help' for more information.\n"
    exit 1
fi 


printf "\033[0;35m"
cat << 'EOF'
______
Made by Millen93
-------
   \
    \
    ....................................................................................................................................
    .....................::::::...............................................................................:::::::...................
    ....................-:::.::-::..........................................................................:--::.::::..................
    ...................:-:-::::..:--::..........................Made by Millen93........................---::..:::--:::.................
    ...................::---:::::...:---:...........................................................:--=-:..::::----=:..................
    ...................:------:::::....:--:::....................................................:----:...::::::----=:..................
    ...................:-------::::......:-:::........................................:........:-=-.....:::::-------=:..................
    ...................::------:::::........:::-::................::::::::::::............:..-=-::....::::::::-------:..................
    ...................::-------::::...........::-:-::-:-=+==++++************++++==+=-:..-=---... ....:::::.::-------:..................
    ....................:-----::::::............::.:-=*##**%%%%%%%%%%%%%%%%%%%%%%%#+*%%#+-...........:::..::::-------:..................
    ....................:-=------:::.......::::..:=+*#%##++#***********************=+##*+*+-.........:....:::::----=-...................
    .....................:---=--::::.......:::.-=***#######*+++=-::::....:::.:-=+***+++=-----: ........:..::--------:...................
    .....................::=--::.:.........::.-++*#%%%#+++-:::-=+*-:-+**+-:-+*#+-::::-==+==----. .......::::::.:--=:....................
    .....................::--::.::::::.......+*=+##*+-..*=.     .=*=.-#*:.+#=:*=.      .:===-::=: .............:---:....................
    ......................-:--::............+#%%%*+=:..=+.......  :+= -:.#+:. +*.......  .-+-:::=: ......:::::::-=:. ...................
    ......................:::-:........... +***##+++:::+:       .. -=.-:-#-.. =#.      .. .=-.:::=.....::......:-:......................
    ......................::.:::::::::..:.-*==-**+-::.-=...      . -:.-:-*-...-+.        . =-.:::-- ..:........::..:....................
    .......................-.:::::::......--:::=+==.::=-........  .-:.:::+=:..-=........  :=...:==:..:.....::......:....................
    .......................=.......:=---#=-=:..:+===:::.        .:-:. :::===-::-..      .:-:.. :-...:-.--=-... ...::....................
    ......................:-.:::::.=-:.:=::... ::======-:......:::....--:::----==:....::::...   ..  .:.:..-:::::..:-....................
    ......................:-===:...:....:::....::.:::---::::::::....::-:::::::::-::::::.... ............. ...::-=-::....................
    .......................=. .. . .....::::::::::......................................   .............. .  .. ..-.....................
    .......................=.... . .....::::............... ....  .       .   . ... ..  ....   ......:..: . ......:.....................
    .......................-. .. . ..:. ........::--:--:.:-..:::............:: .::..:..:----:::....  .  ...  .. ..:.....................
    .......................+. .:.     ...::::--+++====-:..::.::..:.:.:....::::..::.:..:-=***++=-:::....      ... .:.....................
    ..................... =- .::.  ..::--::-=++=-:......  ....:. ....:..:.:... .....   .......:=--::::....    :: .:- ...................
    ..................... =-      ..::------=:. .:::-.:::.   .    ......:....       .:-:.-:::.  .:::::::....      :- ...................
    ......................::     .:-----::..   -=---=.:----.  ..   .::..:::.    .  -==--:=-----:  .....::...      .:....................
    ......................       ::::::...... .=-----.:-----: .:   .::..:..    :  -=---::=------. ...........      .....................
    .........................  .---:::-:.::::..==----.:-----:  :. .:-----:.   .. .=----:.------: .:............  .......................
    ...........................-*=--:.:--:..::.:-----.:-----.    ..-======:.      :----:.-----:...... .......-:.........................
    ...........................:#=.=:...--:..:...:---.:---:.... ..---====-::    ....:--:.---:...... ..... ..:+-.........................
    ............................*+.:-::..:-:......... ......::... :-------:.   ...:....................  ...=+:.........................
    ............................+*:.:-::....:::.........:::...::. .-------:. .:::..:::...............  ....:+=..........................
    ............................:#+...::::....:::::::::::...:---:..-------:: .-:::...::::.........   ......=+:..........................
    .............................-#*:...::::..  ...::::...:------..:..:::....:::::::. .:::....         ...-*-...........................
    ..............................-#*-....::::.......  .::::------:. .... .::---:::::.  .  .............:-=:............................
    ..............................::=+-:............. .:::----::-::::.  ..::-::::::::::   ............::--..............................
    ...........................::::...--:..............:::-::::::::--:. ::::::::::::::.. .. .........-+:...:::..........................
    .......................:::.:.......-=-   .          .::::::::::::.  .::::::::::::..  .          :=:..::.::::.:......................
    ................................:.:+:-.           ..   ...::::.        ..:.....     .           +-.........:........................
    .............................:....+=.::-.                ...  .::::::.:.      .   ..          .--= ....:............................
    ...........................::... .*=...::..           .   ....:---::::::.                    .- == ......::.........................
    ................................-#+-:. ....:                 ...::::::...                  .-. :##=.................................
    .............................. +*:**::. ....::.                                           -+.  --*=-: ..............................
    ...............................+#= -+:.   ...:--.                                       .-:     :%-++...............................
    ............................ .=*-#*..==...    .:--:.                              ...:::-.      +#.%+*-.............................
    ............................:#*++:::..::.....    ..:::.                         .. .::.   ..  .**. *:-- ............................
    ............................+%#-:-     ........      .::.                         ::   ...   -*-  ...#-.............................
    .............................::.  ....     ..........   .:.                      -.  --.   -+=.     :-..............................
    ..................................... .. ...   .........  :.      ..........    -. .+-   -+=.  .. ..................................
    ......................................  ... ...     ...... :.  ..... ..  .     :. .-.  :+=.  .......................................
    ............................................   .....  .  .. :                .-..:.  :=-.  .........................................
    ..............................................     ......... :              .:::   .--. ............................................
    .................................................... ..........           ::.  .....................................................
    ....................................................................................................................................
    ....................................................................................................................................


===== STARTING SCAN =====


EOF

printf "${NC}${YELLOW}===== Installing Required Software =====${NC}\n"

for pkg in "${packages[@]}"; do
    install_if_not_exists "$pkg"
done

install_nmap_vulners

if [[ -v $LOGSTASH ]]; then 
    install_nmapos
    export_to_logstash
fi

# Create directories for logs with date in ISO 8601 format
printf "${YELLOW}===== Creating Directory =====${NC}\n"
if [ -d reports ]; then
  printf "${YELLOW}===== Reports Directory Exists =====${NC}\n"
else
  mkdir -p "reports"
  printf "${GREEN}===== Reports Directory Created =====${NC}\n"
fi



dir=reports/$(date +%Y-%m-%dT%T)
mkdir -p "$dir/active_ports_output" "$dir/service_version" "$dir/vulnerability_scan" "$dir/dirb" "$dir/nikto" "$dir/wp_scan" "$dir/diff"

cd $dir || exit


printf "${YELLOW}===== Searching For Active Hosts In ${network} =====${NC}\n"
# Capture the output of active_hosts_check and store it in an array
active_hosts=($(active_hosts_check "$network"))


printf "${YELLOW}===== Searching For Ports/Services/CVEs In ${network} =====${NC}\n"
# Check if there any http services
  # Pass the array to active_ports_scan
    # Run ports/service/cve scanning
active_ports_scan "${active_hosts[@]}"

rotate_reports

if [[ -v $API_TOKEN_TG ]] && [[ -v $CHAT_ID_TG ]]; then
    differ_check
fi

printf "${GREEN}====================================================================${NC}\n"
