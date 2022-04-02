#!/usr/bin/env bash
export PS3='[Press RETURN for menu, and select number, or 18 when quit] #? > '
red_blod() {
	echo -e "\x1b[1;31m$1\e[0m"
}
red_slim_flash() {
	echo -e "\x1b[5;31m$1\e[0m"
}
red_slim() {
	echo -e "\x1b[31m$1\e[0m"
}
green_blod() {
	echo -e "\x1b[1;32m$1\e[0m"
}
green_slim() {
	echo -e "\x1b[32m$1\e[0m"
}
green_flash() {
	echo -e "\x1b[5;32m$1\e[0m"
}
yellow_blod() {
	echo -e "\x1b[1;33m$1\e[0m"
}
yellow_slim() {
	echo -e "\x1b[33m$1\e[0m"
}
blue_blod() {
    echo -e "\x1b[1;34m$1\e[0m"
}
blue_slim() {
    echo -e "\x1b[34m$1\e[0m"
}
pink_blod() {
    echo -e "\x1b[1;35m$1\e[0m"
}
pink_slim() {
    echo -e "\x1b[35m$1\e[0m"
}
bblue_blod() {
    echo -e "\x1b[1;36m$1\e[0m"
}
bblue_slim() {
    echo -e "\x1b[36m$1\e[0m"
}

echo ""
bblue_slim " ▄█  ███▄▄▄▄      ▄████████  ▄█     ▄██████▄     ▄█    █▄        ███        ▄████████    ▄████████      ";
bblue_slim "███  ███▀▀▀██▄   ███    ███ ███    ███    ███   ███    ███   ▀█████████▄   ███    ███   ███    ███      ";
bblue_slim "███▌ ███   ███   ███    █▀  ███▌   ███    █▀    ███    ███      ▀███▀▀██   ███    █▀    ███    ███      ";
bblue_slim "███▌ ███   ███   ███        ███▌  ▄███         ▄███▄▄▄▄███▄▄     ███   ▀  ▄███▄▄▄      ▄███▄▄▄▄██▀      ";
bblue_slim "███▌ ███   ███ ▀███████████ ███▌ ▀▀███ ████▄  ▀▀███▀▀▀▀███▀      ███     ▀▀███▀▀▀     ▀▀███▀▀▀▀▀        ";
bblue_slim "███  ███   ███          ███ ███    ███    ███   ███    ███       ███       ███    █▄  ▀███████████      ";
bblue_slim "███  ███   ███    ▄█    ███ ███    ███    ███   ███    ███       ███       ███    ███   ███    ███      ";
bblue_slim "█▀    ▀█   █▀   ▄████████▀  █▀     ████████▀    ███    █▀       ▄████▀     ██████████   ███    ███      ";
bblue_slim "             Insighter -- 适用于 CentOS & Ubuntu 系统洞察快速检测工具  v1.0             ███    ███           ";
echo -e "\n"



# WEB Path 设置web目录 默认的话是从/目录去搜索 性能较慢
webpath='/'

### 1.环境检查 ###
prerequisites_setting() {
	yellow_blod "[+] 初始化"
	# 验证是否为root权限
	if [ $UID -ne 0 ]; then
		red_slim_flash "[ERROR] 请使用root权限运行"
		exit 1
	else
		green_slim "[PASS] 当前为root权限"
	fi

	# 判断操作系统是debian系还是centos
	OS='None'

	if [ -e "/etc/os-release" ]; then
		source /etc/os-release
		case ${ID} in
			"debian" | "ubuntu" | "devuan")
				OS='Debian'
				;;
			"centos" | "rhel fedora" | "rhel")
				OS='Centos'
				;;
			*) ;;
		esac
	fi

	if [ $OS = 'None' ]; then
		if command -v apt-get >/dev/null 2>&1; then
			OS='Debian'
			if [ -e "silversearcher-ag_2.2.0-1+b1_amd64.deb" ];then
				dpkg -i silversearcher-ag_2.2.0-1+b1_amd64.deb >/dev/null
			fi
		elif command -v yum >/dev/null 2>&1; then
			OS='Centos'
			if [ -e "the_silver_searcher-2.1.0-1.el7.x86_64.rpm" ];then
				rpm -ivh the_silver_searcher-2.1.0-1.el7.x86_64.rpm >/dev/null
			fi
		else
			red_slim_flash "[ERROR] Insighter脚本不支持该个系统！已退出"
			exit 1
		fi
	fi

	# 安装应急必备工具
	cmdline=(
		"epel-release"
		"net-tools"
		# "telnet"
		# "nc"
		# "lrzsz"
		# "wget"
		# "strace"
		# "htop"
		"tar"
		"lsof"
		# "tcpdump"
		"the_silver_searcher"
		"silversearcher-ag"
	)
	for prog in "${cmdline[@]}"; do

		if [ $OS = 'Centos' ]; then
			if [ "$prog" == "silversearcher-ag" ]; then
				continue
			fi
			soft=$(rpm -q "$prog")
			if echo "$soft" | grep -E '没有安装|未安装|not installed' >/dev/null 2>&1; then
				yum install -y "$prog" >/dev/null 2>&1
				if [ "$?" == "0" ];then
					green_slim "[PASS] 成功安装 $prog"
				else
					red_slim_flash "[ERROR] 安装失败，请检查问题后再次运行... $prog"
				fi
			fi
		else
			if [ "$prog" == "the_silver_searcher" ]; then
				continue
			fi
			if dpkg -L $prog | grep 'does not contain any files' >/dev/null 2>&1; then
				apt install -y "$prog" >/dev/null 2>&1
				if [ "$?"=="0" ];then
					green_slim "[PASS] 成功安装 $prog"
				else
					red_slim_flash "[ERROR] 安装失败，请检查问题后再次运行... $prog"
				fi
			fi
		fi
	done
	echo -e "\n"
}



base_check() {
	yellow_blod "[+] 系统基础配置检查"
	#系统信息
	yellow_slim "[++] 系统信息"
	#当前用户
	echo -e "USER:\t\t$(whoami)" 2>/dev/null
	#版本信息
	echo -e "OS Version:\t$(uname -r)"
	#主机名
	echo -e "Hostname: \t$(hostname -s)"
	#服务器SN
	echo -e "服务器SN: \t$(dmidecode -t1 | ag -o '(?<=Serial Number: ).*')"
	#uptime
	echo -e "Uptime: \t$(uptime | awk -F ',' '{print $1}')"
	#系统负载
	echo -e "系统负载: \t$(uptime | awk '{print $9" "$10" "$11" "$12" "$13}')"
	#cpu信息
	echo -e "CPU info:\t$(ag -o '(?<=model name\t: ).*' </proc/cpuinfo | head -n 1)"
	#cpu核心
	echo -e "CPU 核心:\t$(cat /proc/cpuinfo | grep 'processor' | sort | uniq | wc -l)"
	#ipaddress
	ipaddress=$(ifconfig | ag -o '(?<=inet |inet addr:)\d+\.\d+\.\d+\.\d+' | ag -v '127.0.0.1') >/dev/null 2>&1
	echo -e "IPADDR:\t\t${ipaddress}" | sed ":a;N;s/\n/ /g;ta"
	echo -e "\n"

	#CPU使用率
	yellow_slim "[++] CPU使用率"
	bblue_slim "[Command]: awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null"
	awk '$0 ~/cpu[0-9]/' /proc/stat 2>/dev/null | while read line; do
		echo "$line" | awk '{total=$2+$3+$4+$5+$6+$7+$8;free=$5;\
			print$1" Free "free/total*100"%",\
			"Used " (total-free)/total*100"%"}'
	done
	echo -e "\n"

	#登陆用户
	yellow_slim "登陆用户"
	bblue_slim "[Command]: who"
	who
	echo -e "\n"

	#CPU占用TOP 10
	cpu=$(ps aux | grep -v ^'USER' | sort -rn -k3 | head -10) 2>/dev/null
	yellow_slim "[++] CPU TOP10"
	bblue_slim "[Command]: ps aux | grep -v ^'USER' | sort -rn -k3 | head -10 2>/dev/null"
	echo -e "USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
	echo -e "${cpu}"
	echo -e "\n"

	#内存占用TOP 10
	mem=$(ps aux | grep -v ^'USER' | sort -rn -k4 | head -10) 2>/dev/null
	yellow_slim "[++] 内存占用 TOP10"
	bblue_slim "[Command]: ps aux | grep -v ^'USER' | sort -rn -k4 | head -10 2>/dev/null"
	echo -e "USER        PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND"
	echo -e "${mem}"
	echo -e "\n"

	#内存占用
	yellow_slim "[++] 内存占用"
	bblue_slim "[Command]: free -mh"
	free -mh
	echo -e "\n"

	#剩余空间
	yellow_slim "[++] 剩余空间"
	bblue_slim "[Command]: df -mh"
	df -mh
	echo -e "\n"

	#硬盘挂载
	yellow_slim "[++] 硬盘挂载"
	bblue_slim "[Command]: ag -v '#' </etc/fstab | awk '{print \$1,\$2,\$3}'"
	ag -v "#" </etc/fstab | awk '{print $1,$2,$3}'
	echo -e "\n"

	#安装软件
	yellow_slim "[++] 常用软件"
	bblue_slim "[Command]: which (perl|gcc|g++|python|php|cc|go|node|nodejs|bind|tomcat|clang|ruby|curl|wget|mysql|redis|ssserver|vsftpd|java|apache|apache2|nginx|git|mongodb|docker|tftp|psql|kafka)"
	cmdline=(
		"which perl"
		"which gcc"
		"which g++"
		"which python"
		"which php"
		"which cc"
		"which go"
		"which node"
		"which nodejs"
		"which bind"
		"which tomcat"
		"which clang"
		"which ruby"
		"which curl"
		"which wget"
		"which mysql"
		"which redis"
		"which ssserver"
		"which vsftpd"
		"which java"
		"which apache"
		"which apache2"
		"which nginx"
		"which git"
		"which mongodb"
		"which docker"
		"which tftp"
		"which psql"
		"which kafka"
	)

	for prog in "${cmdline[@]}"; do
		soft=$($prog)
		if [ "$soft" ] 2>/dev/null; then
			echo -e "$soft" | ag -o '\w+$' --nocolor
		fi
	done
	echo -e "\n"

	#HOSTS
	yellow_slim "[++] /etc/hosts"
	bblue_slim "[Command]: cat /etc/hosts | ag -v '#'"
	cat /etc/hosts | ag -v "#"
	echo -e "\n"
}

network_check() {
	yellow_blod "[+] 网络和流量检查"

	#ifconfig
	yellow_slim "[++] ifconfig"
	bblue_slim "[Command]: /sbin/ifconfig -a"
	/sbin/ifconfig -a
	echo -e "\n"

	#网络流量
	yellow_slim "[++] 网络流量 "
	bblue_slim "[Command]: awk ' NR>2' /proc/net/dev"
	echo "Interface    ByteRec   PackRec   ByteTran   PackTran"
	awk ' NR>2' /proc/net/dev | while read line; do
		echo "$line" | awk -F ':' '{print "  "$1"  " $2}' |
		awk '{print $1"   "$2 "    "$3"   "$10"  "$11}'
	done
	echo -e "\n"

	#端口监听
	yellow_slim "[++] 端口监听"
	bblue_slim "[Command]: netstat -tulpen | ag 'tcp|udp.*'"
	echo "Proto Recv-Q Send-Q Local Address           Foreign Address         State       User       Inode      PID/Program name"
	netstat -tulpen | ag 'tcp|udp.*' --nocolor
	echo -e "\n"

	#对外开放端口
	yellow_slim "[++] 对外开放端口"
	bblue_slim "[Command]: netstat -tulpen | awk '{print $1,$4}' | ag -o '.*0.0.0.0:(\d+)|:::\d+'"
	echo "Proto Local Address"
	netstat -tulpen | awk '{print $1,$4}' | ag -o '.*0.0.0.0:(\d+)|:::\d+' --nocolor
	echo -e "\n"

	#网络连接
	yellow_slim "[++] 已建立的网络连接"
	bblue_slim "[Command]: netstat -antop | ag ESTAB"
	echo -e "Proto Recv-Q Send-Q Local Address           Foreign Address         State       PID/Program name     Timer"
	netstat -antop | ag ESTAB --nocolor
	echo -e "\n"

	#连接状态
	yellow_slim "[++] TCP连接状态"
	bblue_slim "[Command]: netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'"
	echo -e "State\tCount"
	netstat -n | awk '/^tcp/ {++S[$NF]} END {for(a in S) print a, S[a]}'
	echo -e "\n"

	#路由表
	yellow_slim "[++] 路由表"
	bblue_slim "[Command]: /sbin/route -nee"
	/sbin/route -nee
	echo -e "\n"

	#路由转发
	yellow_slim "[++] 路由转发"
	bblue_slim "[Command]: more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}'"
	ip_forward=$(more /proc/sys/net/ipv4/ip_forward | awk -F: '{if ($1==1) print "1"}')
	if [ -n "$ip_forward" ]; then
		echo "/proc/sys/net/ipv4/ip_forward 已开启路由转发"
	else
		echo "该服务器未开启路由转发"
	fi
	echo -e "\n"

	#DNS
	yellow_slim "[++] DNS Server"
	bblue_slim "[Command]: ag -o '\d+\.\d+\.\d+\.\d+' --nocolor </etc/resolv.conf"
	ag -o '\d+\.\d+\.\d+\.\d+' --nocolor </etc/resolv.conf
	echo -e "\n"

	#ARP
	yellow_slim "[++] ARP"
	bblue_slim "[Command]: arp -n -a"
	arp -n -a
	echo -e "\n"

	#混杂模式
	yellow_slim "[++] 网卡混杂模式"
	bblue_slim "[Command]: ip link | ag PROMISC"
	if ip link | ag PROMISC >/dev/null 2>&1; then
		echo "网卡存在混杂模式！"
	else
		echo "网卡不存在混杂模式"
	fi
	echo -e "\n"

	#防火墙
	yellow_slim "[++] IPTABLES防火墙"
	bblue_slim "[Command]: iptables -L"
	iptables -L
	echo -e "\n"
}

crontab_check() {
	yellow_blod "[+] 任务计划检查"
	#crontab
	yellow_slim "[++] Crontab"
	bblue_slim "[Command]: crontab -u root -l | ag -v '#'"
	crontab -u root -l | ag -v '#' --nocolor
	echo -e "\n"

	bblue_slim "[Command]: ls -alht /etc/cron.*/*"
	ls -alht /etc/cron.*/*
	echo -e "\n"

	#crontab可疑命令
	yellow_slim "[++] Crontab Backdoor "
	bblue_slim "[Command]: ag '((?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(?:bash\s\-i|fsockopen|nc\s\-e|sh\s\-i|\"/bin/sh\"|\"/bin/bash\"))' /etc/cron* /var/spool/cron/*"
	ag '((?:useradd|groupadd|chattr)|(?:wget\s|curl\s|tftp\s\-i|scp\s|sftp\s)|(?:bash\s\-i|fsockopen|nc\s\-e|sh\s\-i|\"/bin/sh\"|\"/bin/bash\"))' /etc/cron* /var/spool/cron/* --nocolor
	echo -e "\n"
}

env_check() {
	yellow_blod "[+] 环境变量检查"
	#env
	yellow_slim "[++] env"
	bblue_slim "[Command]: env"
	env
	echo -e "\n"

	#PATH
	yellow_slim "[++] PATH"
	bblue_slim "[Command]: echo \$PATH"
	echo "$PATH"
	echo -e "\n"

	#LD_PRELOAD
	yellow_slim "[++] LD_PRELOAD"
	bblue_slim "[Command]: echo \${LD_PRELOAD}"
	if [ ${LD_PRELOAD} ];then
		echo ${LD_PRELOAD}
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"
	
	#LD_ELF_PRELOAD
	yellow_slim "[++] LD_ELF_PRELOAD"
	bblue_slim "[Command]: echo \${LD_ELF_PRELOAD}"
	if [ ${LD_ELF_PRELOAD} ];then
		echo ${LD_ELF_PRELOAD}
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"

	#LD_AOUT_PRELOAD
	yellow_slim "[++] LD_AOUT_PRELOAD"
	bblue_slim "[Command]: echo \${LD_AOUT_PRELOAD}"
	if [ ${LD_AOUT_PRELOAD} ];then
		echo ${LD_AOUT_PRELOAD}
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"

	#PROMPT_COMMAND
	yellow_slim "[++] PROMPT_COMMAND"
	bblue_slim "[Command]: echo \${PROMPT_COMMAND}"
	if [ ${PROMPT_COMMAND} ];then
		echo ${PROMPT_COMMAND}
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"

	#LD_LIBRARY_PATH
	yellow_slim "[++] LD_LIBRARY_PATH"
	bblue_slim "[Command]: echo \${LD_LIBRARY_PATH}"
	if [ ${LD_LIBRARY_PATH} ];then
		echo ${LD_LIBRARY_PATH}
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"

	#ld.so.preload
	yellow_slim "[++] ld.so.preload"
	bblue_slim "[Command]: cat \${preload}"
	preload='/etc/ld.so.preload'
	if [ -e "${preload}" ]; then
		cat ${preload}
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"
}

user_check() {
	yellow_blod "[+] 用户信息检查"
	yellow_slim "[++] 可登陆的用户"
	bblue_slim "[Command]: cat /etc/passwd | ag -v 'nologin$|false$'"
	cat /etc/passwd | ag -v 'nologin$|false$'
	echo -e "\n"
	yellow_slim "[++] passwd文件修改日期"
	bblue_slim "[Command]: stat /etc/passwd | ag -o '(?<=Modify:|最近更改：).*'"
	stat /etc/passwd | ag -o '(?<=Modify:|最近更改：).*' --nocolor
	echo -e "\n"
	yellow_slim "[++] sudoers(请注意NOPASSWD)"
	bblue_slim "[Command]: cat /etc/sudoers | ag -v '#' | sed -e '/^$/d' | ag ALL"
	cat /etc/sudoers | ag -v '#' | sed -e '/^$/d' | ag ALL --nocolor
	echo -e "\n"
	yellow_slim "[++] 登录信息"
	bblue_slim "[Command]: w"
	w
	echo -e "\n"
	bblue_slim "[Command]: last"
	last
	echo -e "\n"
	bblue_slim "[Command]: lastlog"
	lastlog
	echo -e "\n"
	yellow_slim "[++] 登陆成功的IP"
	bblue_slim "[Command]: ag -a accepted /var/log/secure /var/log/auth.* 2>/dev/null | ag -o '\d+\.\d+\.\d+\.\d+' | sort | uniq"
	echo "$(ag -a accepted /var/log/secure /var/log/auth.* 2>/dev/null | ag -o '\d+\.\d+\.\d+\.\d+' | sort | uniq)"
	echo -e "\n"
}

service_check() {
	yellow_blod "[+] 服务状态检查"
	yellow_slim "[++] 正在运行的Service "
	bblue_slim "[Command]: systemctl -l | grep running | awk '{print \$1}'"
	systemctl -l | grep running | awk '{print $1}'
	echo -e "\n"
	yellow_slim "[++] 最近添加的Service "
	bblue_slim "[Command]: ls -alhtR /etc/systemd/system/multi-user.target.wants"
	ls -alhtR /etc/systemd/system/multi-user.target.wants
	echo -e "\n"
	bblue_slim "[Command]: ls -alht /etc/systemd/system/*.wants/*.service | ag -v 'dbus-org'"
	ls -alht /etc/systemd/system/*.wants/*.service | ag -v 'dbus-org'
	echo -e "\n"
}

bash_check() {
	yellow_blod "[+] Bash配置检查"
	#查看history文件
	yellow_slim "[++] History"
	bblue_slim "[Command]: ls -alht /root/.*_history"
	ls -alht /root/.*_history
	echo -e "\n"

	bblue_slim "[Command]: cat ~/.*history | ag '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b' --nocolor | ag -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b'"
	cat ~/.*history | ag '(?<![0-9])(?:(?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2})[.](?:25[0-5]|2[0-4][0-9]|[0-1]?[0-9]{1,2}))(?![0-9])|http://|https://|\bssh\b|\bscp\b|\.tar|\bwget\b|\bcurl\b|\bnc\b|\btelnet\b|\bbash\b|\bsh\b|\bchmod\b|\bchown\b|/etc/passwd|/etc/shadow|/etc/hosts|\bnmap\b|\bfrp\b|\bnfs\b|\bsshd\b|\bmodprobe\b|\blsmod\b|\bsudo\b' --nocolor | ag -v 'man\b|ag\b|cat\b|sed\b|git\b|docker\b|rm\b|touch\b|mv\b|\bapt\b|\bapt-get\b'
	echo -e "\n"

	#/etc/profile
	yellow_slim "[++] /etc/profile "
	bblue_slim "[Command]: cat /etc/profile | ag -v '#'"
	cat /etc/profile | ag -v '#'
	echo -e "\n"

	# $HOME/.profile
	yellow_slim "[++] \$HOME/.profile "
	bblue_slim "[Command]: cat $HOME/.profile | ag -v '#'"
	cat $HOME/.profile | ag -v '#'
	echo -e "\n"

	#/etc/rc.local
	yellow_slim "[++] /etc/rc.local "
	bblue_slim "[Command]: cat /etc/rc.local | ag -v '#'"
	cat /etc/rc.local | ag -v '#'
	echo -e "\n"

	#~/.bash_profile
	yellow_slim "[++] ~/.bash_profile "
	bblue_slim "[Command]: cat ~/.bash_profile | ag -v '#'"
	if [ -e "$HOME/.bash_profile" ]; then
		cat ~/.bash_profile | ag -v '#'
	fi
	echo -e "\n"

	#~/.bashrc
	yellow_slim "[++] ~/.bashrc "
	bblue_slim "[Command]: cat ~/.bashrc | ag -v '#'"
	cat ~/.bashrc | ag -v '#'
	echo -e "\n"

	#bash反弹shell
	yellow_slim "[++] bash反弹shell "
	bblue_slim "[Command]: ps -ef | ag 'bash -i' | ag -v 'ag' | awk '{print \$2}' | xargs -i{} lsof -p {} | ag 'ESTAB'"
	bash_reverse_shell=$(ps -ef | ag 'bash -i' | ag -v 'ag' | awk '{print $2}' | xargs -i{} lsof -p {} | ag 'ESTAB' --nocolor)
	if [ $bash_reverse_shell ];then
		echo $bash_reverse_shell
	else
		green_slim "[PASS]"
	fi
	echo -e "\n"
}

file_check() {
	yellow_blod "[+] 可疑文件检查"
	#系统文件修改时间
	yellow_slim "[++] 系统文件修改时间 "
	bblue_slim "[Command]: stat (/sbin/ifconfig|/bin/ls|/bin/login|/bin/netstat|/bin/top|/bin/ps|/bin/find|/bin/grep|/etc/passwd|/etc/shadow|/usr/bin/curl|/usr/bin/wget|/root/.ssh/authorized_keys)"
	cmdline=(
		"/sbin/ifconfig"
		"/bin/ls"
		"/bin/login"
		"/bin/netstat"
		"/bin/top"
		"/bin/ps"
		"/bin/find"
		"/bin/grep"
		"/etc/passwd"
		"/etc/shadow"
		"/usr/bin/curl"
		"/usr/bin/wget"
		"/root/.ssh/authorized_keys"
	)
	for soft in "${cmdline[@]}"; do
		if [ `command -v $soft` ];then
			echo -e "文件：$soft\t\t\t修改日期：$(stat $soft | ag -o '(?<=Modify:|最近更改：)[\d-\s:]+')"
		fi
	done
	echo -e "\n"

	#隐藏文件
	yellow_slim "[++] 隐藏文件 "
	bblue_slim "[Command]: find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*.""
	find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -name ".*."
	echo -e "\n"

	#tmp目录
	yellow_slim "[++] /tmp "
	bblue_slim "[Command]: ls -alht /tmp /var/tmp /dev/shm "
	ls -alht /tmp /var/tmp /dev/shm 
	echo -e "\n"

	#alias 别名
	yellow_slim "[++] alias "
	bblue_slim "[Command]: alias | ag -v 'git' "
	alias | ag -v 'git'
	echo -e "\n"

	#SUID
	yellow_slim "[++] SUID "
	bblue_slim "[Command]: find / ! -path "/proc/*" -perm -004000 -type f | ag -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps'"
	find / ! -path "/proc/*" -perm -004000 -type f | ag -v 'snap|docker|pam_timestamp_check|unix_chkpwd|ping|mount|su|pt_chown|ssh-keysign|at|passwd|chsh|crontab|chfn|usernetctl|staprun|newgrp|chage|dhcp|helper|pkexec|top|Xorg|nvidia-modprobe|quota|login|security_authtrampoline|authopen|traceroute6|traceroute|ps'
	echo -e "\n"

	#进程存在但文件已经没有了
	yellow_slim "[++] lsof +L1 "
	bblue_slim "[Command]: lsof +L1"
	lsof +L1
	echo -e "\n"

	#近7天改动
	yellow_slim "[++] 近七天文件改动 mtime "
	bblue_slim "[Command]: find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n|vscode' | xargs -i{} ls -alh {}"
	find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -mtime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n|vscode' | xargs -i{} ls -alh {}
	echo -e "\n"

	#近7天改动
	yellow_slim "[++] 近七天文件改动 ctime "
	bblue_slim "[Command]: find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n|vscode|git-core|perl5' | xargs -i{} ls -alh {}"
	find /etc /bin /lib /sbin /dev /root/ /home /tmp /var /usr ! -path "/var/log*" ! -path "/var/spool/exim4*" ! -path "/var/backups*" -ctime -7 -type f | ag -v '\.log|cache|vim|/share/|/lib/|.zsh|.gem|\.git|LICENSE|README|/_\w+\.\w+|\blogs\b|elasticsearch|nohup|i18n|vscode|git-core|perl5' | xargs -i{} ls -alh {}
	echo -e "\n"

	#大文件200mb
	#黑客可能会将数据库、网站打包成一个文件然后下载
	yellow_slim "[++] 大文件>200mb "
	bblue_slim "[Command]: find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | ag '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' --nocolor | ag -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1'"
	find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -size +200M -exec ls -alht {} + 2>/dev/null | ag '\.gif|\.jpeg|\.jpg|\.png|\.zip|\.tar.gz|\.tgz|\.7z|\.log|\.xz|\.rar|\.bak|\.old|\.sql|\.1|\.txt|\.tar|\.db|/\w+$' --nocolor | ag -v 'ib_logfile|ibd|mysql-bin|mysql-slow|ibdata1'
	echo -e "\n"

	#敏感文件
	yellow_slim "[++] 敏感文件 "
	bblue_slim "[Command]: find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f | ag -v '/lib/python' | xargs -i{} ls -alh {}"
	find / ! -path "/lib/modules*" ! -path "/usr/src*" ! -path "/snap*" ! -path "/usr/include/*" -regextype posix-extended -regex '.*sqlmap|.*msfconsole|.*\bncat|.*\bnmap|.*nikto|.*ettercap|.*tunnel\.(php|jsp|asp|py)|.*/nc\b|.*socks.(php|jsp|asp|py)|.*proxy.(php|jsp|asp|py)|.*brook.*|.*frps|.*frpc|.*aircrack|.*hydra|.*miner|.*/ew$' -type f | ag -v '/lib/python' | xargs -i{} ls -alh {}
	echo -e "\n"

	yellow_slim "[++] 可疑黑客文件 "
	bblue_slim "[Command]: find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | ag -v '/pkgs/|/envs/'"
	find /root /home /opt /tmp /var/ /dev -regextype posix-extended -regex '.*wget|.*curl|.*openssl|.*mysql' -type f 2>/dev/null | xargs -i{} ls -alh {} | ag -v '/pkgs/|/envs/'
	echo -e "\n"
}

rootkit_check() {
	yellow_blod "[+] Rootkit检查"
	#lsmod 可疑模块
	yellow_slim "[++] lsmod 可疑模块"
	bblue_slim "[Command]: lsmod | ag -v 'ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet'"
	lsmod | ag -v "ablk_helper|ac97_bus|acpi_power_meter|aesni_intel|ahci|ata_generic|ata_piix|auth_rpcgss|binfmt_misc|bluetooth|bnep|bnx2|bridge|cdrom|cirrus|coretemp|crc_t10dif|crc32_pclmul|crc32c_intel|crct10dif_common|crct10dif_generic|crct10dif_pclmul|cryptd|dca|dcdbas|dm_log|dm_mirror|dm_mod|dm_region_hash|drm|drm_kms_helper|drm_panel_orientation_quirks|e1000|ebtable_broute|ebtable_filter|ebtable_nat|ebtables|edac_core|ext4|fb_sys_fops|floppy|fuse|gf128mul|ghash_clmulni_intel|glue_helper|grace|i2c_algo_bit|i2c_core|i2c_piix4|i7core_edac|intel_powerclamp|ioatdma|ip_set|ip_tables|ip6_tables|ip6t_REJECT|ip6t_rpfilter|ip6table_filter|ip6table_mangle|ip6table_nat|ip6ta ble_raw|ip6table_security|ipmi_devintf|ipmi_msghandler|ipmi_si|ipmi_ssif|ipt_MASQUERADE|ipt_REJECT|iptable_filter|iptable_mangle|iptable_nat|iptable_raw|iptable_security|iTCO_vendor_support|iTCO_wdt|jbd2|joydev|kvm|kvm_intel|libahci|libata|libcrc32c|llc|lockd|lpc_ich|lrw|mbcache|megaraid_sas|mfd_core|mgag200|Module|mptbase|mptscsih|mptspi|nf_conntrack|nf_conntrack_ipv4|nf_conntrack_ipv6|nf_defrag_ipv4|nf_defrag_ipv6|nf_nat|nf_nat_ipv4|nf_nat_ipv6|nf_nat_masquerade_ipv4|nfnetlink|nfnetlink_log|nfnetlink_queue|nfs_acl|nfsd|parport|parport_pc|pata_acpi|pcspkr|ppdev|rfkill|sch_fq_codel|scsi_transport_spi|sd_mod|serio_raw|sg|shpchp|snd|snd_ac97_codec|snd_ens1371|snd_page_alloc|snd_pcm|snd_rawmidi|snd_seq|snd_seq_device|snd_seq_midi|snd_seq_midi_event|snd_timer|soundcore|sr_mod|stp|sunrpc|syscopyarea|sysfillrect|sysimgblt|tcp_lp|ttm|tun|uvcvideo|videobuf2_core|videobuf2_memops|videobuf2_vmalloc|videodev|virtio|virtio_balloon|virtio_console|virtio_net|virtio_pci|virtio_ring|virtio_scsi|vmhgfs|vmw_balloon|vmw_vmci|vmw_vsock_vmci_transport|vmware_balloon|vmwgfx|vsock|xfs|xt_CHECKSUM|xt_conntrack|xt_state|raid*|tcpbbr|btrfs|.*diag|psmouse|ufs|linear|msdos|cpuid|veth|xt_tcpudp|xfrm_user|xfrm_algo|xt_addrtype|br_netfilter|input_leds|sch_fq|ib_iser|rdma_cm|iw_cm|ib_cm|ib_core|.*scsi.*|tcp_bbr|pcbc|autofs4|multipath|hfs.*|minix|ntfs|vfat|jfs|usbcore|usb_common|ehci_hcd|uhci_hcd|ecb|crc32c_generic|button|hid|usbhid|evdev|hid_generic|overlay|xt_nat|qnx4|sb_edac|acpi_cpufreq|ixgbe|pf_ring|tcp_htcp|cfg80211|x86_pkg_temp_thermal|mei_me|mei|processor|thermal_sys|lp|enclosure|ses|ehci_pci|igb|i2c_i801|pps_core|isofs|nls_utf8|xt_REDIRECT|xt_multiport|iosf_mbi|qxl|cdc_ether|usbnet"
	echo -e "\n"
	
	#Rootkit 内核模块
	yellow_slim "[++] Rootkit 内核模块"
	bblue_slim "[Command]: grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms"
	kernel=$(grep -E 'hide_tcp4_port|hidden_files|hide_tcp6_port|diamorphine|module_hide|module_hidden|is_invisible|hacked_getdents|hacked_kill|heroin|kernel_unlink|hide_module|find_sys_call_tbl|h4x_delete_module|h4x_getdents64|h4x_kill|h4x_tcp4_seq_show|new_getdents|old_getdents|should_hide_file_name|should_hide_task_name' </proc/kallsyms)
	if [ -n "$kernel" ]; then
		red_slim_flash "[ERROR] 存在内核敏感函数, 疑似Rootkit内核模块"
		echo "$kernel"
	else
		green_slim "[PASS] 未找到敏感Rootkit 内核模块"
	fi
	echo -e "\n"

	#可疑的.ko模块
	yellow_slim "[++] 可疑的.ko模块"
	bblue_slim "[Command]: find / ! -path "/proc/*" ! -path "/usr/lib/modules/*" ! -path "/boot/*" -regextype posix-extended -regex '.*\.ko'"
	ko_module=$(find / ! -path "/proc/*" ! -path "/usr/lib/modules/*" ! -path "/boot/*" -regextype posix-extended -regex '.*\.ko')
	if [ $ko_module ];then
		red_slim_flash "$ko_module"
	else
		green_slim "[PASS] 未找到可疑的.ko模块"
	fi
	echo -e "\n"
}

ssh_check() {
	yellow_blod "[+] SSH检查"
	#SSH 爆破IP
	yellow_slim "[++] SSH爆破"
	bblue_slim "[Command]: ag -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25"
	bblue_slim "[Command]: ag -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25"
	if [ $OS = 'Centos' ]; then
		ag -a 'authentication failure' /var/log/secure* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25
	else
		ag -a 'authentication failure' /var/log/auth.* | awk '{print $14}' | awk -F '=' '{print $2}' | ag '\d+\.\d+\.\d+\.\d+' | sort | uniq -c | sort -nr | head -n 25
	fi
	echo -e "\n"

	#SSHD
	yellow_slim "[++] SSHD "
	bblue_slim "[Command]: stat /usr/sbin/sshd"
	stat /usr/sbin/sshd
	echo -e "\n"

	#SSH 后门配置检查
	yellow_slim "[++] SSH 后门配置 "
	bblue_slim "[Command]: grep LocalCommand <~/.ssh/config"
	bblue_slim "[Command]: grep ProxyCommand <~/.ssh/config"
	if [ -e "$HOME/.ssh/config" ]; then
		grep LocalCommand <~/.ssh/config
		grep ProxyCommand <~/.ssh/config
	else
		green_slim "[PASS] 未发现SSH 后门配置文件"
	fi
	echo -e "\n"

	#SSH inetd后门检查
	yellow_slim "[++] SSH inetd后门检查 "
	bblue_slim "[Command]: grep -E '(bash -i)' </etc/inetd.conf"
	if [ -e "/etc/inetd.conf" ]; then
		grep -E '(bash -i)' </etc/inetd.conf
	else
		green_slim "[PASS] 未发现SSH inetd后门"
	fi
	echo -e "\n"

	#SSH key
	yellow_slim "[++] SSH key"
	bblue_slim "[Command]: cat /root/.ssh/authorized_keys"
	sshkey=${HOME}/.ssh/authorized_keys
	if [ -e "${sshkey}" ]; then
		cat ${sshkey}
	else
		green_slim "[PASS] SSH key文件不存在"
	fi
	echo -e "\n"
}

webshell_check() {
	yellow_blod "[+] Webshell检查"
	#PHP webshell查杀
	yellow_slim "[++] PHP webshell查杀"
	ag --php -l -s -i 'array_map\(|pcntl_exec\(|proc_open\(|popen\(|assert\(|phpspy|c99sh|milw0rm|eval?\(|\(gunerpress|\(base64_decoolcode|spider_bc|shell_exec\(|passthru\(|base64_decode\s?\(|gzuncompress\s?\(|gzinflate|\(\$\$\w+|call_user_func\(|call_user_func_array\(|preg_replace_callback\(|preg_replace\(|register_shutdown_function\(|register_tick_function\(|mb_ereg_replace_callback\(|filter_var\(|ob_start\(|usort\(|uksort\(|uasort\(|GzinFlate\s?\(|\$\w+\(\d+\)\.\$\w+\(\d+\)\.|\$\w+=str_replace\(|eval\/\*.*\*\/\(' $webpath
	ag --php -l -s -i '^(\xff\xd8|\x89\x50|GIF89a|GIF87a|BM|\x00\x00\x01\x00\x01)[\s\S]*<\?\s*php' $webpath
	ag --php -l -s -i '\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\/*\s]*((\$_(GET|POST|REQUEST|COOKIE)\[.{0,25})|(base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\(]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25}))' $webpath
	ag --php -l -s -i '\$\s*(\w+)\s*=[\s\(\{]*(\$_(GET|POST|REQUEST|COOKIE)\[.{0,25});[\s\S]{0,200}\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec)\b[\/*\s]*\(+[\s"\/*]*(\$\s*\1|((base64_decode|gzinflate|gzuncompress|gzdecode|str_rot13)[\s\("]*\$\s*\1))' $webpath
	ag --php -l -s -i '\b(filter_var|filter_var_array)\b\s*\(.*FILTER_CALLBACK[^;]*((\$_(GET|POST|REQUEST|COOKIE|SERVER)\[.{0,25})|(eval|assert|ass\\x65rt|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec))' $webpath
	ag --php -l -s -i "\b(assert|eval|system|exec|shell_exec|passthru|popen|proc_open|pcntl_exec|include)\b\s*\(\s*(file_get_contents\s*\(\s*)?[\'\"]php:\/\/input" $webpath
	echo -e "\n"
	
	#JSP webshell查杀
	yellow_slim "[++] JSP webshell查杀"
	ag --jsp -l -s -i '<%@\spage\simport=[\s\S]*\\u00\d+\\u00\d+|<%@\spage\simport=[\s\S]*Runtime.getRuntime\(\).exec\(request.getParameter\(|Runtime.getRuntime\(\)' $webpath
	echo -e "\n"
}

poison_check() {
	yellow_blod "[+] 供应链投毒检测"
	#Python2 pip 检测
	yellow_slim "[++] Python2 pip 检测"
	bblue_slim "[Command]: pip freeze | ag 'istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request='"
	pip freeze | ag "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request="
	echo -e "\n"

	#Python3 pip 检测
	yellow_slim "[++] Python3 pip 检测"
	bblue_slim "[Command]: pip3 freeze | ag 'istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request='"
	pip3 freeze | ag "istrib|djanga|easyinstall|junkeldat|libpeshka|mumpy|mybiubiubiu|nmap-python|openvc|python-ftp|pythonkafka|python-mongo|python-mysql|python-mysqldb|python-openssl|python-sqlite|virtualnv|mateplotlib|request="
	echo -e "\n"
}

miner_check() {
	yellow_blod "[+] 挖矿木马检查"
	#常规挖矿进程检测
	yellow_slim "[++] 常规挖矿进程检测"
	normal_miner_1=$(ps aux | ag "systemctI|kworkerds|init10.cfg|wl.conf|crond64|watchbog|sustse|donate|proxkekman|test.conf|/var/tmp/apple|/var/tmp/big|/var/tmp/small|/var/tmp/cat|/var/tmp/dog|/var/tmp/mysql|/var/tmp/sishen|ubyx|cpu.c|tes.conf|psping|/var/tmp/java-c|pscf|cryptonight|sustes|xmrig|xmr-stak|suppoie|ririg|/var/tmp/ntpd|/var/tmp/ntp|/var/tmp/qq|/tmp/qq|/var/tmp/aa|gg1.conf|hh1.conf|apaqi|dajiba|/var/tmp/look|/var/tmp/nginx|dd1.conf|kkk1.conf|ttt1.conf|ooo1.conf|ppp1.conf|lll1.conf|yyy1.conf|1111.conf|2221.conf|dk1.conf|kd1.conf|mao1.conf|YB1.conf|2Ri1.conf|3Gu1.conf|crant|nicehash|linuxs|linuxl|Linux|crawler.weibo|stratum|gpg-daemon|jobs.flu.cc|cranberry|start.sh|watch.sh|krun.sh|killTop.sh|cpuminer|/60009|ssh_deny.sh|clean.sh|\./over|mrx1|redisscan|ebscan|barad_agent|\.sr0|clay|udevs|\.sshd|/tmp/init|xmr|xig|ddgs|minerd|hashvault|geqn|\.kthreadd|httpdz|pastebin.com|sobot.com|kerbero|2t3ik|ddgs|qW3xt|ztctb" | ag -v 'ag')
	normal_miner_2=$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/run/*" ! -path "/boot/*" -regextype posix-extended -regex '.*systemctI|.*kworkerds|.*init10.cfg|.*wl.conf|.*crond64|.*watchbog|.*sustse|.*donate|.*proxkekman|.*cryptonight|.*sustes|.*xmrig|.*xmr-stak|.*suppoie|.*ririg|gg1.conf|.*cpuminer|.*xmr|.*xig|.*ddgs|.*minerd|.*hashvault|\.kthreadd|.*httpdz|.*kerbero|.*2t3ik|.*qW3xt|.*ztctb|.*miner.sh' -type f)
	if [ "$normal_miner_1" -o "$normal_miner_2" ];then
		echo -e "$normal_miner_1 \n$normal_miner_2"
	else
		green_slim "[PASS] 未检测到常规挖矿进程"
	fi
	echo -e "\n"

	#Ntpclient 挖矿木马检测
	yellow_slim "[++] Ntpclient 挖矿木马检测"
	ntpclient_miner_1=$(find / ! -path "/proc/*" ! -path "/sys/*" ! -path "/boot/*" -regextype posix-extended -regex 'ntpclient|Mozz')
	ntpclient_miner_1=$(ls -alh /tmp/.a /var/tmp/.a /run/shm/a /dev/.a /dev/shm/.a 2>/dev/null)
	if [ "$ntpclient_miner_1" -o "$ntpclient_miner_2" ];then
		echo -e "$ntpclient_miner_1 \n$ntpclient_miner_2"
	else
		green_slim "[PASS] 未检测到Ntpclient 挖矿木马"
	fi
	echo -e "\n"

	#WorkMiner 挖矿木马检测
	yellow_slim "[++] WorkMiner 挖矿木马检测"
	work_miner_1=$(ps aux | ag "work32|work64|/tmp/secure.sh|/tmp/auth.sh" | ag -v 'ag')
	work_miner_2=$(ls -alh /tmp/xmr /tmp/config.json /tmp/secure.sh /tmp/auth.sh /usr/.work/work64 2>/dev/null)
	if [ "$work_miner_1" -o "$work_miner_2" ];then
		echo -e "$work_miner_1 \n$work_miner_2"
	else
		green_slim "[PASS] 未检测到WorkMiner 挖矿木马"
	fi
	echo -e "\n"
}

rkhunter_install() {
	yellow_blod "[+] Rookit查杀"
	#Rkhunter查杀
	yellow_slim "[++] Rkhunter查杀"
	bblue_slim "[Command]: rkhunter --checkall --sk | ag -v 'OK|Not found|None found'"
	if rkhunter >/dev/null 2>&1; then
		rkhunter --checkall --sk | ag -v 'OK|Not found|None found'
	else
		if [ -e "/tmp/rkhunter.tar.gz" ]; then
			cd /tmp && tar -zxvf /tmp/rkhunter.tar.gz >/dev/null 2>&1
			cd /tmp/rkhunter-1.4.6/ && ./installer.sh --install >/dev/null 2>&1
			rkhunter --checkall --sk | ag -v 'OK|Not found|None found'
		else
			echo -e "未找到 rkhunter.tar.gz 软件包，正在尝试下载..."
			curl --connect-timeout 5 -o /tmp/rkhunter.tar.gz https://nchc.dl.sourceforge.net/project/rkhunter/rkhunter/1.4.6/rkhunter-1.4.6.tar.gz >/dev/null
			sleep 10
			tar -zxvf /tmp/rkhunter.tar.gz >/dev/null 2>&1
			cd /tmp/rkhunter-1.4.6/ && ./installer.sh --install >/dev/null 2>&1
			rkhunter --checkall --sk | ag -v 'OK|Not found|None found'
		fi
	fi
}

risk_check() {
	yellow_blod "[+] 风险&漏洞检查"
	#Redis弱密码检测
	yellow_slim "[++] Redis弱密码检测"
	bblue_slim "[Command]: cat /etc/redis/redis.conf 2>/dev/null | ag '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)'"
	redis_weak_password=$(cat /etc/redis/redis.conf 2>/dev/null | ag '(?<=requirepass )(test|123456|admin|root|12345678|111111|p@ssw0rd|test|qwerty|zxcvbnm|123123|12344321|123qwe|password|1qaz|000000|666666|888888)')
	if [ "$redis_weak_password" ];then
		echo $redis_weak_password
	else
		green_slim "[PASS] 未检测到Redis弱密码"
	fi
	echo -e "\n"
}


helper() {
	bblue_slim "-------------------------"
	yellow_blod "[1] 系统基础配置检查"
	yellow_slim "[++] 系统信息"
	yellow_slim "[++] CPU使用率"
	yellow_slim "[++] CPU TOP10"
	yellow_slim "[++] 内存占用 TOP10"
	yellow_slim "[++] 内存占用"
	yellow_slim "[++] 剩余空间"
	yellow_slim "[++] 硬盘挂载"
	yellow_slim "[++] 常用软件"
	yellow_slim "[++] /etc/hosts"
	bblue_slim "-------------------------"
	yellow_blod "[2] 网络和流量检查"
	yellow_slim "[++] ifconfig"
	yellow_slim "[++] 网络流量 "
	yellow_slim "[++] 端口监听"
	yellow_slim "[++] 对外开放端口"
	yellow_slim "[++] 已建立的网络连接"
	yellow_slim "[++] TCP连接状态"
	yellow_slim "[++] 路由表"
	yellow_slim "[++] 路由转发"
	yellow_slim "[++] DNS Server"
	yellow_slim "[++] ARP"
	yellow_slim "[++] 网卡混杂模式"
	yellow_slim "[++] IPTABLES防火墙"
	bblue_slim "-------------------------"
	yellow_blod "[3] 任务计划检查"
	yellow_slim "[++] Crontab"
	yellow_slim "[++] Crontab Backdoor "
	bblue_slim "-------------------------"
	yellow_blod "[4] 环境变量检查"
	yellow_slim "[++] env"
	yellow_slim "[++] PATH"
	yellow_slim "[++] LD_PRELOAD"
	yellow_slim "[++] LD_ELF_PRELOAD"
	yellow_slim "[++] LD_AOUT_PRELOAD"
	yellow_slim "[++] PROMPT_COMMAND"
	yellow_slim "[++] LD_LIBRARY_PATH"
	yellow_slim "[++] ld.so.preload"
	bblue_slim "-------------------------"
	yellow_blod "[5] 用户信息检查"
	yellow_slim "[++] 可登陆的用户"
	yellow_slim "[++] passwd文件修改日期"
	yellow_slim "[++] sudoers(请注意NOPASSWD)"
	yellow_slim "[++] 登录信息"
	yellow_slim "[++] 登陆成功的IP"
	bblue_slim "-------------------------"
	yellow_blod "[6] 服务状态检查"
	yellow_slim "[++] 正在运行的Service "
	yellow_slim "[++] 最近添加的Service "
	bblue_slim "-------------------------"
	yellow_blod "[7] Bash配置检查"
	yellow_slim "[++] History"
	yellow_slim "[++] /etc/profile "
	yellow_slim "[++] \$HOME/.profile "
	yellow_slim "[++] /etc/rc.local "
	yellow_slim "[++] ~/.bash_profile "
	yellow_slim "[++] ~/.bashrc "
	yellow_slim "[++] bash反弹shell "
	bblue_slim "-------------------------"
	yellow_blod "[8] 可疑文件检查"
	yellow_slim "[++] 系统文件修改时间 "
	yellow_slim "[++] 隐藏文件 "
	yellow_slim "[++] /tmp "
	yellow_slim "[++] alias "
	yellow_slim "[++] SUID "
	yellow_slim "[++] lsof +L1 "
	yellow_slim "[++] 近七天文件改动 mtime "
	yellow_slim "[++] 近七天文件改动 ctime "
	yellow_slim "[++] 大文件>200mb "
	yellow_slim "[++] 敏感文件 "
	yellow_slim "[++] 可疑黑客文件 "
	bblue_slim "-------------------------"
	yellow_blod "[9] Rootkit检查"
	yellow_slim "[++] lsmod 可疑模块"
	yellow_slim "[++] Rootkit 内核模块"
	yellow_slim "[++] 可疑的.ko模块"
	bblue_slim "-------------------------"
	yellow_blod "[10] SSH检查"
	yellow_slim "[++] SSH爆破"
	yellow_slim "[++] SSHD "
	yellow_slim "[++] SSH 后门配置 "
	yellow_slim "[++] SSH inetd后门检查 "
	yellow_slim "[++] SSH key"
	bblue_slim "-------------------------"
	yellow_blod "[11] Webshell检查"
	yellow_slim "[++] PHP webshell查杀"
	yellow_slim "[++] JSP webshell查杀"
	bblue_slim "-------------------------"
	yellow_blod "[12] 供应链投毒检测"
	yellow_slim "[++] Python2 pip 检测"
	yellow_slim "[++] Python3 pip 检测"
	bblue_slim "-------------------------"
	yellow_blod "[13] 挖矿木马检查"
	yellow_slim "[++] 常规挖矿进程检测"
	yellow_slim "[++] Ntpclient 挖矿木马检测"
	yellow_slim "[++] WorkMiner 挖矿木马检测"
	bblue_slim "-------------------------"
	yellow_blod "[14] Rookit查杀"
	yellow_slim "[++] Rkhunter查杀"
	bblue_slim "-------------------------"
	yellow_blod "[15] 风险&漏洞检查"
	yellow_slim "[++] Redis弱密码检测"
}

prerequisites_setting
# base_check
# network_check
# crontab_check
# env_check
# user_check
# service_check
# bash_check
# file_check
# rootkit_check
# ssh_check
# webshell_check
# poison_check
# miner_check
# rkhunter_install
# risk_check

#Todo: 每个模块选择后自动把输出保存到文件
if [ ! -d "./results" ];then
	mkdir -p ./results
fi
result='./results'

select option in "运行所有检查" "系统基础配置检查" "网络和流量检查" "任务计划检查" "环境变量检查" "用户信息检查" "服务状态检查" "Bash配置检查" "可疑文件检查" "Rootkit检查" "SSH检查" "Webshell检查" "供应链投毒检测" "挖矿木马检查" "Rookit查杀" "风险&漏洞检查" "脚本详细说明" "退出脚本"
do 
	case $option in
		"运行所有检查")
			log_file=$result/'all_check'_`date +%Y%m%d%H%M%S`_"$option".log
			base_check | tee -a $log_file
			network_check | tee -a $log_file
			crontab_check | tee -a $log_file
			env_check | tee -a $log_file
			user_check | tee -a $log_file
			service_check | tee -a $log_file
			bash_check | tee -a $log_file
			file_check | tee -a $log_file
			rootkit_check | tee -a $log_file
			ssh_check | tee -a $log_file
			webshell_check | tee -a $log_file
			poison_check | tee -a $log_file
			miner_check | tee -a $log_file
			rkhunter_install | tee -a $log_file
			risk_check | tee -a $log_file
			;;
		"系统基础配置检查")
			base_check | tee -a $result/'base_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"网络和流量检查")
			network_check | tee -a $result/'network_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"任务计划检查")
			crontab_check | tee -a $result/'crontab_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"环境变量检查")
			env_check | tee -a $result/'env_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"用户信息检查")
			user_check | tee -a $result/'user_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"服务状态检查")
			service_check | tee -a $result/'service_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"Bash配置检查")
			bash_check | tee -a $result/'bash_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"可疑文件检查")
			file_check | tee -a $result/'file_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"Rootkit检查")
			rootkit_check | tee -a $result/'rootkit_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"SSH检查")
			ssh_check | tee -a $result/'ssh_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"Webshell检查")
			webshell_check | tee -a $result/'webshell_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"供应链投毒检测")
			poison_check | tee -a $result/'poison_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"挖矿木马检查")
			miner_check | tee -a $result/'miner_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"Rookit查杀")
			rkhunter_install | tee -a $result/'rkhunter_install'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"风险&漏洞检查")
			risk_check | tee -a $result/'risk_check'_`date +%Y%m%d%H%M%S`_"$option".log | less -e -B -R  ;;
		"脚本详细说明")
			helper | less -e -B -R  ;;
		"退出脚本")
			break ;;
		*)
			red_blod "Sorry, Wrong Selection, Please Input Number." ;;
	esac
done
clear