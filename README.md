<h1 align="center"><i>Экзаменационное задание по ПМ.02. Организация сетевого администрирования</i></h1>
<i><strong>Сценарий.</strong></i><br>
<i>Вы являетесь системным администратором компании в которой имеется гетерогенная сеть с использованием решений различных производителей. Серверная на основе Windows Server 2019 (Desktop и Core) AltLinux Server, есть клиентские машины на основе Windows 10 Pro и AltLinux.  Часть сервисов уже развёрнута на компьютерах организации. В головном офисе компании имеется роутер для подключения к сети провайдера. Провайдер предоставляет подключение к глобальной сети, шлюз по умолчанию, а также выделенные адреса для подключения. В компании имеются сотрудники, которые работают на удалёнке на корпоративных ПК на основе Simply Linux, которые должны иметь доступ к информационной системе компании. Кроме того, в планах руководства есть желание построить корпоративный портал на отказоустойчивой инфраструктуре.</i>
<i>Конечной целью является полноценное функционирование инфраструктуры предприятия в пределах соответствующих регионов.
Имеющаяся инфраструктура представлена на диаграмме:</i>
<br>
<br>

![Image alt](https://github.com/NewErr0r/Qualification_Exam/blob/main/topologya.png)

<strong> Таблица адресации: </strong>
<br>

![Image alt](https://github.com/NewErr0r/Qualification_Exam/blob/main/tableaddressing.png)

<i>Ваша задача донастроить инфраструктуру организации в соответствии с требованиями руководства компании.</i>
<br>
<i>Сервер DC является контроллером домена на нём развёрнуты сервисы Active Directory(домен – Oaklet.org), DNS.</i>
<br>


<h1>Базовая конфигурация (подготовительные настройки):</h1>
<ul>
    <li><strong>FW (name, nameserver, gateway, addressing, nat, dhcp-relay)</strong></li>
</ul>
<br>
<pre>
set system hostname FW
set system name-server 77.88.8.8
set protocols static route 0.0.0.0/0 next-hop 200.100.100.254 distance 1

set interface ethernet eth0 address 200.100.100.200/24
set interface ethernet eth1 address 172.20.0.1/24
set interface ethernet eth2 address 172.20.2.1/23

set nat source rule 1 outhboun-interface eth0
set nat source rule 2 outhboun-interface eth0
set nat source rule 1 source address 172.20.0.0/24
set nat source rule 2 source address 172.20.2.0/23
set nat source rule 1 translation address masquerade
set nat source rule 2 translation address masquerade

set service dhcp-relay interface eth1
set service dhcp-relay interface eth2
set service dhcp-relay server 172.20.0.100
set service dhcp-relay relay-options relay-agents-packets discard
</pre>

<ul>
    <li><strong>FS (Disabled Firewall)</strong></li>
</ul>
<br>
<pre>
powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled false
</pre>

<ul>
    <li><strong>SRV (name, addressing)</strong></li>
</ul>
<br>
<pre>
su -
hostnamectl set-hostname SRV.Oaklet.org
reboot
</pre>
<pre>
ЦУС -> Сеть -> Ethernet-интерфейсы
IP: 172.20.3.100/23
Шлюз по умолчанию: 172.20.2.1
DNS-серверы: 172.20.0.100 77.88.8.8
Домены поиска: Oaklet.org
</pre>

<ul>
    <li>APP-V (name, addressing, nat)</strong></li>
</ul>
<br>
<pre>
hostnamectl set-hostname APP-V

mkdir /etc/net/ifaces/enp0s8
cp /etc/net/ifaces/enp0s3/* /etc/net/ifaces/enp0s8

echo 200.100.100.200/24 >> /etc/net/ifaces/enp0s3/ipv4address
echo default via 200.100.100.254 > /etc/net/ifaces/enp0s3/ipv4route
echo 10.116.0.10/14 >> /etc/net/ifaces/enp0s8/ipv4address
systemctl restart network
ip link set up enp0s3
ip link set up enp0s8

echo nameserver 77.88.8.8 > /etc/resolv.conf
apt-get update
apt-get install firewalld -y
systemctl enable --now firewalld

firewall-cmd --permanent --zone=trusted --add-interface=enp0s8
firewall-cmd --permanent --add-masquerade
firewall-cmd --reload

echo net.ipv4.ip_forward=1 >> /etc/sysctl.conf
sysctl -p
</pre>

<ul>
    <li>APP-L (name, addressing)</strong></li>
</ul>
<br>
<pre>
hostnamectl set-hostname APP-L
echo 10.116.0.20/14 >> /etc/net/ifaces/enp0s3/ipv4address
echo default via 10.116.0.10 > /etc/net/ifaces/enp0s3/ipv4route
systemctl restart network
ip link set up enp0s3
echo nameserver 77.88.8.8 > /etc/resolv.conf
</pre>

<ul>
    <li>APP-R (name, addressing)</strong></li>
</ul>
<br>
<pre>
hostnamectl set-hostname APP-R
echo 10.116.0.30/14 >> /etc/net/ifaces/enp0s3/ipv4address
echo default via 10.116.0.10 > /etc/net/ifaces/enp0s3/ipv4route
systemctl restart network
ip link set up enp0s3
echo nameserver 77.88.8.8 > /etc/resolv.conf
</pre>

<ul>
    <li>CLI-R (name, addressing)</strong></li>
</ul>
<br>
<pre>
su -
hostnamectl set-hostname CLI-R
reboot

ЦУС -> Сеть -> Ethernet-интерфейсы
IP: 200.100.100.10/24
Шлюз по умолчанию: 200.100.100.254
DNS-серверы: 77.88.8.8 172.20.0.100 

su - 
ip link set up enp0s3
</pre>

<h1>Элементы доменной инфраструктуры:</h1>
<ul>
    <li><strong>На сервере контроллера домена необходимо развернуть следующую организационную структуру:</strong></li>
</ul>
<br>

![Image alt](https://github.com/NewErr0r/Qualification_Exam/blob/main/departament.png)
<br>

<pre>
New-ADOrganizationalUnit -Name ADM
New-ADOrganizationalUnit -Name Sales
New-ADOrganizationalUnit -Name Delivery
New-ADOrganizationalUnit -Name Development

New-ADGroup "ADM" -path 'OU=ADM,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Sales" -path 'OU=Sales,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Delivery" -path 'OU=Delivery,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Frontend" -path 'OU=Development,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose
New-ADGroup "Backend" -path 'OU=Development,DC=Oaklet,DC=org' -GroupScope Global -PassThru –Verbose

New-ADUser -Name "Director" -UserPrincipalName "Director@Oaklet.org" -Path "OU=ADM,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Secretary" -UserPrincipalName "Secretary@Oaklet.org" -Path "OU=ADM,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Alice" -UserPrincipalName "Alice@Oaklet.org" -Path "OU=Sales,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Bob" -UserPrincipalName "Bob@Oaklet.org" -Path "OU=Sales,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Polevikova" -UserPrincipalName "Polevikova@Oaklet.org" -Path "OU=Delivery,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Morgushko" -UserPrincipalName "Morgushko@Oaklet.org" -Path "OU=Development,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true
New-ADUser -Name "Radjkovith" -UserPrincipalName "Radjkovith@Oaklet.org" -Path "OU=Development,DC=Oaklet,DC=org" -AccountPassword(ConvertTo-SecureString P@ssw0rd -AsPlainText -Force) -Enabled $true

Add-AdGroupMember -Identity ADM Director, Secretary
Add-AdGroupMember -Identity Sales Alice, Bob
Add-AdGroupMember -Identity Delivery Polevikova
Add-AdGroupMember -Identity Frontend Morgushko
Add-AdGroupMember -Identity Backend Radjkovith
</pre>
