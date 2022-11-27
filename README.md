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
    <li><strong>DC (DNS)</strong></li>
</ul>
<br>
<pre>
Add-DnsServerPrimaryZone -NetworkId "172.20.0.0/24" -ReplicationScope Domain
Add-DnsServerPrimaryZone -NetworkId "172.20.2.0/24" -ReplicationScope Domain
Add-DnsServerPrimaryZone -NetworkId "172.20.3.0/24" -ReplicationScope Domain
Add-DnsServerResourceRecordPtr -ZoneName 0.20.172.in-addr.arpa -Name 100 -PtrDomainName dc.Oaklet.org
Add-DnsServerResourceRecordA -Name "FS" -ZoneName "Oaklet.org" -AllowUpdateAny -IPv4Address "172.20.0.200" -CreatePtr
Add-DnsServerResourceRecordA -Name "SRV" -ZoneName "Oaklet.org" -AllowUpdateAny -IPv4Address "172.20.3.100" -CreatePtr
<br>
А так же для дальнейшей работы приложения и веб-сайта по доменным именам:
Add-DnsServerResourceRecordCName -Name "www" -HostNameAlias "SRV.Oaklet.org" -ZoneName "Oaklet.org"
Add-DnsServerPrimaryZone -Name first -ReplicationScope "Forest" –PassThru
Add-DnsServerResourceRecordA -Name "app" -ZoneName "first" -AllowUpdateAny -IPv4Address "200.100.100.200"
</pre>

<ul>
    <li><strong>FS (Disabled Firewall)</strong></li>
</ul>
<br>
<pre>
powershell
Set-NetFirewallProfile -Profile Domain,Public,Private -Enabled false
</pre>
<pre>
Add-Computer
    Администратор
    P@ssw0rd
        Oaklet.org
Restart-Computer
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
su -
apt-get update
apt-get install -y task-auth-ad-sssd
system-auth write ad Oaklet.org SRV Oaklet 'Администратор' 'P@ssw0rd'
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
<br>

<ul>
    <li><strong>Должны быть настроены следующие GPO:</strong></li>
    <ul>
        <li>отключить OneDrive ( имя политики onedrive);</li>
        <li>Запретить чтение информации со съёмных носителей ( имя политики removable media);</li>
        <li>Отключить использование камер (имя политики camera);</li>
        <li>Запретить любые изменения персонализации рабочего стола ( имя политики desktop);</li>
    </ul>
</ul>
<pre>
New-GPO -Name "onedrive" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация компьютера -> Политики -> Административные шаблоны -> Компоненты Windows -> OneDrive -> Запретить использование OneDrive для хранения файлов (включить)
<br>
New-GPO -Name "removable media" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация компьютера -> Политики -> Административные шаблоны -> Система -> Доступ к съемным запоминающим устройствам -> Съемные запоминающие устройства всех классов: Запретить любой доступ (включить)
Конфигурация пользователя -> Политики -> Административные шаблоны -> Система -> Доступ к съемным запоминающим устройствам -> Съемные запоминающие устройства всех классов: Запретить любой доступ (включить)
<br>
New-GPO -Name "camera" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация компьютера -> Политики -> Административные шаблоны -> Компоненты Windows -> Камера -> Разрешить использование камер (Отключить)
<br>
New-GPO -Name "desktop" | New-GPLink -Target "DC=Oaklet,DC=org"
Конфигурация пользователя -> Политики -> Административные шаблоны -> Панель управления -> Персонализация
<br>
powershell
gpupdate /force
</pre>

<ul>
    <li><strong>Для обеспечения отказоустойчивости сервер контроллера домена должен выступать DHCP failover для подсети Clients:</strong></li>
    <ul>
        <li>Он должен принимать управление в случае отказа основного DHCP сервера;</li>
    </ul>
</ul>

<pre>
Install-WindowsFeature DHCP –IncludeManagementTools
Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\ServerManager\Roles\12 -Name ConfigurationState -Value 2
Restart-Service -Name DHCPServer -Force
<br>
Add-DhcpServerv4Scope -Name “Clients-failover” -StartRange 172.20.2.1 -EndRange 172.20.3.254 -SubnetMask 255.255.254.0 -State InActive
Set-DhcpServerv4OptionValue -ScopeID 172.20.2.0 -DnsDomain Oaklet.org -DnsServer 172.20.0.200,77.88.8.8 -Router 172.20.2.1
Add-DhcpServerv4ExclusionRange -ScopeID 172.20.2.0 -StartRange 172.20.2.1 -EndRange 172.20.2.1
Add-DhcpServerv4ExclusionRange -ScopeID 172.20.2.0 -StartRange 172.20.3.100 -EndRange 172.20.3.100
Set-DhcpServerv4Scope -ScopeID 172.20.2.0 -State Active
</pre>

<ul>
    <li><strong>Организуйте DHCP сервер на базе SRV</strong></li>
    <ul>
        <li>Используйте подсеть Clients учётом существующей инфраструктуры в таблице адресации;</li>
        <li>Клиенты CLI-L и CLI-W получают адрес и все необходимые сетевые параметры по DHCP, обеспечивая связность с сетью Интернет и подсетью Servers;</li>
    </ul>
</ul>
<p>Через веб-интерфейс "https://localhost:8080": </p>

![Image alt](https://github.com/NewErr0r/Qualification_Exam/blob/main/dhcp-web.png)

<ul>
    <li><strong>Организуйте сервер времени на базе SRV</strong></li>
    <ul>
        <li>Данный сервер должен использоваться всеми ВМ внутри региона Office;</li>
        <li>Сервер считает собственный источник времени верным;</li>
    </ul>
</ul>

<pre>
apt-get install -y chrony

vi /etc/chronyd.conf
    allow 172.20.0.0/24
    allow 172.20.2.0/23
    
systemctl enable --now chronyd
</pre>

<p><strong>DC, FS</p></strong>
<pre>
Start-Service W32Time
w32tm /config /manualpeerlist:172.20.3.100 /syncfromflags:manual /reliable:yes /update
Restart-Service W32Time
</pre>

<p><strong>CLI-W</p></strong>
<pre>
New-NetFirewallRule -DisplayName "NTP" -Direction Inbound -LocalPort 123 -Protocol UDP -Action Allow
</pre>
<pre>
Start-Service W32Time
w32tm /config /manualpeerlist:172.20.3.100 /syncfromflags:manual /reliable:yes /update
Restart-Service W32Time
</pre>
<pre>
Set-Service -Name W32Time -StartupType Automatic
</pre>

<p><strong>CLI-L</p></strong>
<pre>
su -
vi /etc/chronyd.conf
    pool 172.20.3.100 iburst
    allow 172.20.2.0/23
    
systemctl restart chronyd
</pre>

<p><strong>FW</p></strong>
<pre>
configure
set system ntp server 172.20.3.100
commit
save
</pre>

<ul>
    <li><strong>Все клиенты региона Office должны быть включены в домен</strong></li>
    <ul>
        <li>С клиентов должен быть возможен вход под любой учётной записью домена;</li>
        <li>На клиентах должны применятся настроенные групповые политики;</li>
        <li>Необходимо обеспечить хранение перемещаемого профиля пользователя Morgushko;</li>
    </ul>
</ul>
<p><strong>CLI-W</p></strong>
<pre>
Rename-Computer -NewName CLI-W
Restart-Computer
</pre>
<pre>
Add-Computer
    Администратор
    P@ssw0rd
        Oaklet.org
Restart-Computer
</pre>

<p><strong>CLI-L</p></strong>
<pre>
su -
hostnamectl set-hostname CLI-L.Oaklet.org
reboot
</pre>
<pre>
su - 
apt-get update
apt-get install -y task-auth-ad-sssd
system-auth write ad Oaklet.org CLI-L Oaklet 'Администратор' 'P@ssw0rd'
reboot
</pre>

<ul>
    <li><strong>Организуйте общий каталог для ВМ CLI-W и CLI-L на базе FS:</strong></li>
    <ul>
        <li>Хранение файлов осуществляется на диске, реализованном по технологии RAID5;</li>
        <li>Создать общую папку для пользователей;</li>
        <li>Публикуемый каталог D:\opt\share;</li>
        <li>Смонтируйте каталог на клиентах /mnt/adminshare и D:\adminshare соответственно;</li>
        <li>Разрешите чтение и запись на всех клиентах:
        <ul><li>Определить квоту максимальный размер в 20 мб для пользователей домена;</li></ul>
        </li>
        <li>Монтирование каталогов должно происходить автоматически;</li>        
    </ul>
</ul>

<pre>
diskpart

select disk 1
attrib disk clear readonly
convert dynamic

select disk 2
attrib disk clear readonly
convert dynamic

select disk 3
attrib disk clear readonly
convert dynamic

select disk 4
attrib disk clear readonly
convert dynamic

select disk 5
attrib disk clear readonly
convert dynamic

create volume raid disk=1,2,3,4,5

select volume 0
assign letter=B

select volume 3
assign letter=D
format fs=ntfs
</pre>
