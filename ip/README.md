# Unsavoury IP Route Blackholing

Having worked on my [DNS Malware Blacklister](dns) I always wanted to get around to using OSPF with our network to steer the less savoury parts of the Internet to an IDS; or as I am lazy I simply blackhole the 'filth'.  The thing holding me back was finding a regularly updated list that I could trivially use...then I found [Emerging Threats](http://emergingthreats.net/) (and later on [ZeuS Tracker](https///zeustracker.abuse.ch/)).

The idea was to have a script regularly download the latest copy, if necessary, of the blacklist and populate the local routing table of the Linux box with the contents.  Quagga would be running on the box so that the box could join an OSPF domain and advertise that traffic to the listed IP's should go to it (either to be blackholed, analysed or IDS'd), rather than to follow their normal path out onto the Internet.  Simple!

The only real complication is creating a link between your 'blackhole' and the core of your network.  As we have Cisco kit, which is *terrible* at [IPIP](http://en.wikipedia.org/wiki/IP_tunnel) and [GRE](http://en.wikipedia.org/wiki/Generic_Routing_Encapsulation) tunnelling but are rather good at the Layer-2 stuff, we use a VLAN (ID 600 in this case) to accomplish this.  If you know what you are doing, a trivial change is to use an IPIP/GRE tunnel instead (the advantage being that your do not have a wide Layer-2 VLAN spanning across your core) and run OSPF over that.  You might also notice that 'bond0' is referred to in the network configuration bit on the Linux side, this is as on the server edge switch side we provision port-channels to our servers and like to tag addition VLANs down this port-channel like so:

    interface Port-channel13
     description truffle.it
     switchport trunk encapsulation dot1q
     switchport trunk native vlan 142
     switchport trunk allowed vlan 142,600
     switchport mode trunk

Of course if you do not use a port-channel and instead like to use dedicated links (why?) then obviously this is only an implementation/deployment amendment.

Another thing worth mentioning, is my use of Link-Local addresses ('169.254.0.0/16') on the OSPF links.  You might prefer to use [RFC1918 addresses](http://en.wikipedia.org/wiki/Private_network), or alternatively some real public IP assignment, again, this is down to a matter of taste.

## Configuration

### Cisco IOS
Each core switch/router can take part in the OSPF domain by adding something like the following to your configuration file:

    interface Vlan600
     description filthpit
     ip address 169.254.5.6 255.255.255.248
    !
    router ospf 600
     router-id 169.254.5.6
     log-adjacency-changes
     passive-interface default
     no passive-interface Vlan600
     network 169.254.5.0 0.0.0.7 area 0

### Debian Linux

To get this working you will need to have installed:

 * vlan
 * iproute
 * quagga

You will also need to [download my script ('badroutes2quagga')](https///github.com/jimdigriz/network-layer-protection/blob/master/ip/badroutes2quagga) which does the leg work of fetching the blacklist and inserting it into the local routing process:

    # wget "https://raw.github.com/jimdigriz/network-layer-protection/master/ip/badroutes2quagga" -O /usr/local/sbin/badroutes2quagga
    # chmod +x /usr/local/sbin/badroutes2quagga

There should not be much to edit in the script, however if you want to decide not to use the Emerging Threats or the ZeuS Tracker lists (you have to use at least one) then you simply comment out either 'ET' or 'ZEUS' respectively at the top of the file.

Now edit '/etc/quagga/daemons' so that 'zebra' and 'ospfd' is set to 'yes' and then:

    # echo "hostname truffle.it.soas.ac.uk" > /etc/quagga/zebra.conf
    # echo "password whatever" >> /etc/quagga/zebra.conf
    # chmod 600 /etc/quagga/zebra.conf
    # cp -a /etc/quagga/zebra.conf /etc/quagga/ospfd.conf
    # /etc/init.d/quagga start
    
    # echo "100 filthpit" >> /etc/iproute2/rt_realms
    # echo "50 2 * * * root /usr/local/sbin/badroutes2quagga" > /etc/cron.d/local-quagga 
    # /etc/init.d/cron reload

In your '/etc/network/interfaces' file you should add something like:
    
    auto vlan0600
    iface vlan0600 inet static
            vlan-raw-device bond0
            address 169.254.5.1
            netmask 255.255.255.248
    
            up        ip link set dummy0 up
            up        /usr/local/sbin/badroutes2quagga force
            pre-down  ip route list realm filthpit | xargs -I{} -P2 sh -c 'ip route del {}'
            pre-down  ip link set dummy0 down

You might be asking why we use the [dummy](http://www.faqs.org/docs/linux_network/x-087-2-iface.interface.html#X-087-2-IFACE.INTERFACE.DUMMY) interface, it is because we need to blackhole the traffic.  Most people would use 'lo', however if you have IP forwarding enabled you will find that you get a loop on your loopback interface as the TTL on the IP packet spins down to zero.  Not really a biggy but to me feels like the right way to do things.

### Quagga OSPFd

To configure quagga's OSPF daemon you will need to telnet into it using something like:
    
    ac56@truffle:~$ telnet localhost ospfd
    Trying 127.0.0.1...
    Connected to localhost.
    Escape character is '^]'.
    
    Hello, this is Quagga (version 0.99.10).
    Copyright 1996-2005 Kunihiro Ishiguro, et al.
    
    
    User Access Verification
    
    Password: 
    truffle.it.soas.ac.uk> en
    truffle.it.soas.ac.uk# conf t
    truffle.it.soas.ac.uk(config)#

Afterwards it's a case of adding the following:
    
    router ospf
     ospf router-id 169.254.5.1
     redistribute kernel
     passive-interface default
     no passive-interface vlan0600
     network 169.254.5.0/29 area 0.0.0.0
     distribute-list KERNELOUT out kernel
    
    ! your IP ranges - *not* to be blacklisted!
    ! special use
    access-list KERNELOUT deny 10.0.0.0/8
    access-list KERNELOUT deny 192.168.0.0/16
    access-list KERNELOUT deny 172.16.0.0/12
    access-list KERNELOUT deny 169.254.0.0/16
    ! public allocation - add your public allocations here
    access-list KERNELOUT deny 195.195.176.0/21
    access-list KERNELOUT deny 212.219.136.0/22
    access-list KERNELOUT deny 212.219.236.0/22
    access-list KERNELOUT deny 193.63.73.0/24
    access-list KERNELOUT deny 195.195.131.224/28
    ! accept everything else
    access-list KERNELOUT permit any

Once added, you should be able to save your changes:
    
    truffle.it.soas.ac.uk(config)# end
    truffle.it.soas.ac.uk# write
    Configuration saved to /etc/quagga/ospfd.conf
    truffle.it.soas.ac.uk# exit
    Connection closed by foreign host.
    ac56@truffle:~$ 

## Making Things Live

Okay, you should be able to ask Quagga if it sees any OSPF neighbours:

    truffle.it.soas.ac.uk> show ip ospf neighbor 
    
    Neighbor ID     Pri State           Dead Time Address         Interface            RXmtL RqstL DBsmL
    169.254.5.5       1 Full/Backup       32.035s 169.254.5.5     vlan0600:169.254.5.1     0     0     0
    169.254.5.6       1 Full/DR           39.212s 169.254.5.6     vlan0600:169.254.5.1     0     0     0

From the Cisco core box end (we have two, hence the output above) you should be able ask:

    6509-1#show ip ospf 600 neighbor 
    
    Neighbor ID     Pri   State           Dead Time   Address         Interface
    169.254.5.1       1   FULL/DROTHER    00:00:32    169.254.5.1     Vlan600
    169.254.5.5       1   FULL/BDR        00:00:36    169.254.5.5     Vlan600

If you do not see the above then something is wrong and you will need to recheck things, otherwise you are set to go.

From the Cisco core end you should see that no routes are being advertised:
    
    6509-1#show ip route ospf 600
    6509-1#

On the Linux box to bring things into life, all you have to do is issue (will take some time):
    
    truffle:/home/ac56# ifup vlan0600
    Set name-type for VLAN subsystem. Should be visible in /proc/net/vlan/config
    Added VLAN with VID == 600 to IF -:bond0:-

A few seconds later you should see about 8000 new routes appear at your core:
    
    6509-1#show ip route ospf 600
         194.204.14.0/32 is subnetted, 1 subnets
    O E2    194.204.14.151 [110/20] via 169.254.5.1, 00:00:29, Vlan600
         212.117.163.0/32 is subnetted, 4 subnets
    O E2    212.117.163.17 [110/20] via 169.254.5.1, 00:00:29, Vlan600
    O E2    212.117.163.162 [110/20] via 169.254.5.1, 00:00:29, Vlan600
    O E2    212.117.163.164 [110/20] via 169.254.5.1, 00:00:29, Vlan600
    O E2    212.117.163.165 [110/20] via 169.254.5.1, 00:00:29, Vlan600
         195.207.15.0/32 is subnetted, 1 subnets
    O E2    195.207.15.79 [110/20] via 169.254.5.1, 00:00:29, Vlan600
    O E2 204.52.255.0/24 [110/20] via 169.254.5.1, 00:00:29, Vlan600
         218.25.203.0/32 is subnetted, 1 subnets
    O E2    218.25.203.5 [110/20] via 169.254.5.1, 00:00:29, Vlan600
         194.8.194.0/32 is subnetted, 1 subnets
    [snipped]

Pretty nifty eh?  It will keep it's self all up to date too.

If you want to stop this, all you have to do is issue:
    
    truffle:/home/ac56# ifdown vlan0600
    Removed VLAN -:vlan0600:-

After a few moments you should find all the routes have been removed.

## Things To Explore

### Packet Sniffing
Well, if you have installed [tcpdump](http://www.tcpdump.org/), then you can see the live 'filth' that is arriving at your box:

    # tcpdump -i vlan0600 -n -p ip and not net 224.0.0.0/24

A rather nifty command I worked out if you would like to record too that traffic as well as see it (without having to resort to using [wireshark](http://www.wireshark.org/)):

    # tcpdump -i vlan0600 -n -p ip and not net 224.0.0.0/24 -s 0 -w - -U | tee /tmp/dump | tcpdump -r - -n

You will probably see a sizable amount of DNS traffic going your way, so you might want to amend the tcpdump filter to also include '`not port 53`' too.

### Tunneling

Now that you have all the 'filth' coming to your box, you might want to re-route it elsewhere.  Trivial to do by adding something like the following to your '/etc/network/interfaces' file:

    auto filthpit
    iface filthpit inet static
            address 169.254.0.0
            netmask 255.255.255.255
            pointopoint 169.254.0.1
    
            pre-up    if [ -z "$(grep vlan0600 /etc/network/run/ifstate)" ]; then echo "must have vlan0600 up first"; exit 1; fi
    
            pre-up    ip tunnel add filthpit mode ipip remote `<REMOTE-IP>` local `<LOCAL-IP>` ttl 64
            post-down ip tunnel del filthpit
    
            up        ip route add default dev filthpit table filthpit
            up        ip rule add dev vlan0600 table filthpit
            up        sysctl -q net.ipv4.conf.filthpit.forwarding=1
            up        sysctl -q net.ipv4.conf.vlan0600.forwarding=1
            up        sysctl -q net.ipv4.conf.vlan0600.rp_filter=0
            pre-down  sysctl -q net.ipv4.conf.vlan0600.rp_filter=1
            pre-down  sysctl -q net.ipv4.conf.vlan0600.forwarding=0
            pre-down  ip rule del dev vlan0600 table filthpit
            pre-down  ip route del default dev filthpit table filthpit

You will also need to type:
    
    # echo "100 filthpit" >> /etc/iproute2/rt_tables

Once you have done all this, when you bring up the 'filthpit' interface, you should find all the traffic is re-routed down the IPIP tunnel to the IP you specified in `<REMOTE-IP>`.  In theory the other end of the tunnel should be able to run a [honeypot](http://en.wikipedia.org/wiki/Honeypot_(computing)) and communicate back to the originator of the traffic.

**N.B.** a better solution, if it is possible, would be to use a [TC filter](http://lartc.org/howto/lartc.qdisc.filters.html) and the ['mirred' action class](http://www.linuxfoundation.org/collaborate/workgroups/networking/ifb) to do all the above.  This would remove the need for using a seperate routing table and give you the option of replicating the traffic to multiple destinations.  If anyone works this out, I have run out of time to play with this, then do [get intouch](/contact).

### Apache
    
    NameVirtualHost 169.254.0.0:80
    #Listen 169.254.0.0:80
    
    LogFormat "%h {%{X-Forwarded-For}i} %u %t %{Host}i \"%r\" %>s \"%{Referer}i\" \"%{User-agent}i\"" routeblackhole
    
    `<VirtualHost 169.254.0.0:80>`
      ServerName *
    
      `<Location />`
        Order Allow,Deny
      `</Location>`
    
      # usually our logs are ~1MB a day, however due to torrent clients they occasionly bounce to 150MB!
      SetEnvIfNoCase User-Agent Azureus dontlog
      SetEnvIfNoCase User-Agent Torrent dontlog
    
      LogLevel info
      CustomLog "|exec /usr/bin/cronolog -S /var/local/routeblackhole/access.log /var/local/routeblackhole/access-%Y%m%d.log" routeblackhole env=!dontlog
      ErrorLog /dev/null
    
      ErrorDocument 403 "Problems, not a mistyped address?  We possibly have mis-listed this website to prevent computer infections.  If so, please email bofh@example.com and state the website you were visiting"
    `</VirtualHost>`
