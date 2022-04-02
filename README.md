# Insighter

系统洞察快速检测工具

[![asciicast](https://asciinema.org/a/483508.svg)](https://asciinema.org/a/483508)

### 功能模块

1. 系统基础配置检查
    1. 系统信息
    2. CPU使用率
    3. 当前登录的用户 (tty为本地登录 / pts为远程登录)
    4. CPU使用率 TOP 10
    5. 内存使用率 TOP 10
    6. 系统内存使用情况
    7. 磁盘剩余空间
    8. 硬盘挂载条目 /etc/fstab
    9. 常用软件安装情况
    10. /etc/hosts
2. 网络和流量检查
    1. 网卡信息
    2. 各个网卡流量
    3. 端口监听
    4. 对外开放端口
    5. 已建立的网络连接 (State: ESTABLISHED)
    6. 已建立的TCP连接总数 (State: ESTABLISHED)
    7. 路由表
    8. 路由转发配置
    9. DNS 服务器信息
    10. ARP表
    11. 网卡混杂模式
    12. IPTABLES防火墙
3. 计划任务检查
    1. root用户的计划任务
    2. Crontab可疑命令检查
4. 环境变量检查
    1. 所有环境变量
    2. PATH
    3. LD_PRELOAD
    4. LD_ELF_PRELOAD
    5. LD_AOUT_PRELOAD
    6. PROMPT_COMMAND
    7. LD_LIBRARY_PATH
    8. ld.so.preload
5. 用户信息检查
    1. 可登陆的用户
    2. /etc/passwd文件修改日期
    3. sudoers(请注意NOPASSWD)
    4. 当前登录的用户 (tty为本地登录 / pts为远程登录)
    5. 登陆成功的IP
6. 服务状态检查
    1. 正在运行的服务
    2. 最近添加的服务
7. Bash配置检查
    1. 查看history文件
    2. 检查history中的可疑命令
    3. 查看/etc/profile文件
    4. 查看\$HOME/.profile文件
    5. 查看/etc/rc.local文件
    6. 查看~/.bash_profile文件
    7. 查看~/.bashrc文件
    8. 检查bash反弹shell
8. 可疑文件检查
    1. 检查常用系统命令文件修改时间
    2. 检查系统隐藏文件
    3. 查看/tmp目录
    4. 检查alias别名
    5. 检查SUID
    6. 检查进程存在但文件已经不存在的情况
    7. 查找近7天改动的文件(mtime)
    8. 查找近7天改动的文件(ctime)
    9. 操作大于200MB的文件
    10. 查找敏感文件
    11. 查找可疑黑客文件
9. Rootkit检查
    1. 检查lsmod可疑模块
    2. 检查Rootkit内核模块
    3. 查找可疑的.ko模块
10. SSH检查
    1. 检查SSH爆破IP
    2. 检查SSHD程序
    3. SSH 检查SSH后门配置
    4. 检查SSH inetd后门
    5. 检查SSH key文件
11. Webshell检查
    1. PHP webshell查杀
    2. JSP webshell查杀
12. pip投毒检测
    1. Python2 pip 检测
    2. Python3 pip 检测
13. 挖矿木马检查
    1. 常规挖矿进程检测
    2. Ntpclient 挖矿木马检测
    3. WorkMiner 挖矿木马检测
14. Rookit查杀
    1. Rkhunter查杀
15. 风险漏洞检查
    1. Redis弱密码检测