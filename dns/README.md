# Protecting Users with DNS Malware Blacklisting

Blacklisting domains that are known to host malware is a simple way to discovery and stall malware on your organisation's network.  You can use it to prevent users, or at least warn them severely, from installing it in the first place and discover malware making dubious DNS lookups on your network.  As a good network administrator is one that maximises laziness, we want to avoid the issues of false positives; mainly as then this increases the amount of contact with have with the users and that is just asking for trouble.  The instructions here not only cover how to blacklist domains, but also to keep your list automatically up to date, and add the functionality so that users themselves can most of the time bypass what they consider to be a false positive listing.

Blacklist sources on where malware lives is hard to come by, as searching online really only gives you hits for DNS mail based blacklisting to be used on MTAs.  The only ones I have found are:

 * http://www.malwaredomains.com/
 * https://zeustracker.abuse.ch/
 * http://hosts-file.net/ - honkingly large but [encompasses much more than just malware](http://hosts-file.net/?s=policy)
 * http://www.malware.com.br/

This page describes how to use a number of lists you wish to use, some of which are listed above, and set up an infrastructure that involves next to zero maintainance.  You might be interested to know that at my work place, a UK university ([SOAS](http://www.soas.ac.uk/)) with 4000 students and 600 staff, started using this system back in July 2008-ish and I have had no problems, and most importantly no contact with the users themselves, in regards to its deployment.

If you have any problems, queries, or suggestions for improvement then do please [contact me](/contact).

## Requirements

You need to have a already functioning installation of [Unbound](http://unbound.net/) running as your organisation's recursive DNS server.  You might prefer to use [BIND9](http://www.isc.org/software/bind), [MaraDNS](http://www.maradns.org/) or some other resolver however to do so you will need to adapt my shell script (should be straight forward, do email me for assistance if you get stuck) and instructions accordingly, although the Apache bit should remain the same.  How to do this all is beyond the scope of this article.

In addition to this you will need a seperate server with a the Apache webserver installed on it that is able to make recursive DNS queries all by it's self.  In addition, you will need the following installed and *configured* on the box:

 * apache2
 * mod_apreq (libapreq2 too)
 * mod_setenvif
 * mod_proxy (mod_proxy_http too)
 * mod_perl - plus the modules Apache2::Request (libapache2-request-perl), Net::DNS (libnet-dns-perl), Template Toolkit (libtemplate-perl) and I18N::AcceptLanguage (libi18n-acceptlanguage-perl)
 * [optional] cronolog

## Downloads

Everything is available via my generic 'network layer protection' git tree at [https://github.com/jimdigriz/network-layer-protection](https///github.com/jimdigriz/network-layer-protection).

All the interesting bits live under the 'dns' directory:
    
    alex@berk:/usr/src/network-layer-protection$ find dns
    dns
    dns/dnshijack.apache
    dns/blacklist2dns
    dns/dnshijack
    dns/dnshijack/DNShijack.pm
    dns/dnshijack/templates
    dns/dnshijack/templates/en
    dns/dnshijack/templates/en/not-blocked.tml
    dns/dnshijack/templates/en/main.tml

## Configuring the Infrastructure

### The Update Script
This is where all the action is, if you are not interested in the executive summary then skip this paragraph.  The script collects lists of domains from the sources you enable, validates them, ignores the unparsable bits and then produces a 'neutral' output format that can be trivially used to produce the format expected by unbound (and also for any other DNS servers, patches welcomed!).  When possible, the HTTP Last-Modified field is used to both lower the load on the remote server and to avoid re-downloading lists that have not changed since the last check.  When HTTP Last-Modified is not available, the script falls back to using MD5 sums.  The script unfortunately is rather long as no list is in the same format and the method that has to be used to fetch the list differs for each.  However, after all these complications, the script can work out if an update has occurred and if so will *only* trigger off a restart of the DNS server when required.

Download the [blacklist2dns](https///github.com/jimdigriz/network-layer-protection/blob/master/dns/blacklist2dns) script, make it executable and place it in `/usr/local/sbin/`.  You will need to make a few minor amendments at the top to match your setup:

    # enable debugging (0/1)
    DEBUG=0
    
    # location to put temporary files at
    WORKDIR=/var/tmp
    
    ## information to put into the outputted zone file
    # how to handle DNS lookups to blacklisted domain ('redirect'/'refuse')
    TYPE=redirect
    # FQDN (remember trailing '.') to redirect domain to (only for 'TYPE=redirect')
    DST_HOST=ids.example.com.
    # FQDN for MX lookups to domain (comment out to not use)
    #DST_MAIL=localhost.
    
    ## DNS blacklist sources to use
    # http://www.malwaredomains.com/
    MALWAREDOMAINS=1
    # https://zeustracker.abuse.ch/blocklist.php
    ZEUS=1
    # http://amada.abuse.ch/blocklist.php - NO LONGER MAINTAINED!
    AMADA=1
    # https://spyeyetracker.abuse.ch/blocklist.php (amada includes spyeye)
    SPYEYE=0
    # http://www.malware.com.br/lists.shtml
    MALWAREBR=0
    # http://www.malware.com.br/conficker.shtml
    MALWAREBR_CONFICKER=1
    
    # grep'able list of domains to whitelist (comment out to not use)
    #WHITELIST=/var/local/blacklist2dns.whitelist
    
    ## DNS server output location (comment out to skip)
    # unbound
    UNBOUND=/etc/unbound/local-dnshijack

These should be the only lines you need to amend.  If you simply want to prevent the DNS lookups working (and not to have a 'self-help' whitelisting service as detailed below functioning) then set 'TYPE' to 'refuse'.  Otherwise you will need to enter in a [FQDN](http://en.wikipedia.org/wiki/Fully_qualified_domain_name) (it is *crucial* that you terminate it with a '.', unless you know what you are doing) to say where you want the DNS lookups to go instead.  You also get the option to redirect the MX records (if you do not, then none will exist and you will get NXDOMAIN) by populating 'DST_MAIL' with a FQDN.

Once configured, you should be able to give it a test run by typing as root (this can take some time so be patient):
    
    # blacklist2dns force

Once it runs you should see some output printed to stdout (and stderr if there are errors) plus a new directory and some files in `WORKDIR`; this is in additional to the updated 'local-dnshijack' file lurking in '/etc/unbound/'.  If you re-run the script again, it should do nothing as the timestamps of the lists (and the contents for those lists that do not support timestamping) should match your local copies (ie. it's unchanged).

### The DNS Server

To configure Unbound is dead easy, you just add the line at the end of the main "server:" section (before the 'python' and 'remote' sections start) to say:

    include: "/etc/unbound/local-dnshijack"

If you now restart unbound you should find it now works.

### Scheduling the Updates

If you create a file '/etc/cron.d/local-unbound' with the following contents:
    
    #MAILTO=hostmaster
    PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin
    
    # every 24 hours check for updates
    # N.B. for each DNS server you should put a different minutely setting of at least five minutes
    #      as when unbound restarts you will find for about ten seconds you will not get any DNS
    #      lookups functioning.  Spreading the updates means only one DNS server is down at a time
    27 2   * * * root   nice -n10 /usr/local/sbin/blacklist2dns && nice -n5 unbound-checkconf && /etc/init.d/unbound restart
    
    # using http://habilis.net/cronic/ instead to cut down inbox noise
    #27 2  * * * root   cronic sh -c 'nice -n10 blacklist2dns; RC=$?; [ $RC -eq 1 ] && exit 0; [ $RC -gt 1 ] && exit $RC; nice -n5 unbound-checkconf && /etc/init.d/unbound restart'

This will check for updates every six hours at seventeen minutes past the hour.  As the note in the above chunk states, you should choose different minutely intervals for each of your DNS servers to avoid downtime; as obviously Unbound will not service DNS queries whilst being restarted which can take some time.

If none of the lists have been updated since the last run, or if there was a problem running the 'blacklist2dns' script, or the outputed config file is broken, then no restart of Unbound will take place.  You should, if you have configured cron correctly, receive an email stating what went horribly wrong if the script failed to run.

To avoid seeing "`unbound[7907:0] warning: increased limit(open files) from 1024 to 8248`" all the time when you restart unbound, you should add the following lines to '/etc/default/unbound':
    
    ulimit    -n 16384
    ulimit -H -n 32768

### The Webserver Componment

The element that makes this bit cook are:

 * 'dnshijack.apache' - the Apache 'dnshijack' VirtualHost snippet which is to be placed in '/etc/apache2/sites-available/' and then create a softlink from there to '/etc/apache2/sites-enabled/'
 * the directory 'dnshijack' which should be placed at '/var/local/dnshijack/'
To get the dnshijack'ing code working you will need to only edit the Apache VirtualHost file, '/etc/apache2/sites-available/dnshijack'.  You need to:
 * amend the IP ranges listed in the `<Proxy>` section.  These are the IP addresses of your client workstation (and will be the ranges your webserver will be happy to service and proxy for).  Failure to set these properly can result in your webserver becoming an open proxy!
 * tweak the 'NameVirtualHost 1.2.3.4' and `<VirtualHost 1.2.3.4:80>` bits to match the IP address of 'ids.example.com' that you used in the 'malwaredomains2unbound' script above

You will also need to tweak the section listing details about your installation in that file too:

    
    PerlSetEnv dnshijackNS                "1.1.1.1"
    PerlSetEnv dnshijackREALM             "example.com"
    PerlSetEnv dnshijackCONTACT_NAME      "Firstname Surname"
    ServerAdmin                           "me@example.com"
    PerlSetEnv dnshijackKEY               "TYPE SOME RANDOM SECRET HERE SO MASH KEYBOARD OR SOMETHING"
    PerlSetEnv dnshijackDEFAULT_LANGUAGE  "en"


You need to amend it as follows:

 * **`dnshijackNS`:** points to your *organisation's* regular DNS server(s) - If you need to enter more than one nameserver then seperate them with spaces
 * **`dnshijackREALM`:** is your organisations domain, if you do not have one use 'localnet'
 * **`dnshijackCONTACT_NAME`:** you need to give your full name and email address ('ServerAdmin') so the users know who to contact when things go wrong
 * **`dnshijackKEY`:** you need to set this to something random.  This is a server side secret cookie so that people are not able to trick the webserver into proxying websites for them unless it is actually permitted
 * **`dnshijackDEFAULT_LANGUAGE`:** you might want to amend if your primary language is not english, it's a i18n abrieviation

You need to configure your webserver to run it's own recursive DNS server that functions completely independently from your organisations one so you should tweak your '/etc/resolv.conf' file to use the nameserver at '127.0.0.1'.  Without this, your webserver when proxying requests would simply find it's-self talking back to it's-self in a nasty loop when someone tries to go to a blacklisted domain.  This you obviously do not want to happen.

All you need to do is restart Apache and you should have a fully functional DNS blacklisting system active.  When you try to access a blacklisted domain with your web browser you will be redirected to a 'blacklisted' page giving a simple explaination of why the site has been disabled.  If it is considered a false positive then a simple button "accept responsibility" will enable the user to get through to the site they want.

## How It Works

It should be pretty obvious why the user sees the disabled page ((as instead of the real IP address being returned for a blacklisted the webserver one is returned)), the whitelisting system might need some explaination.

When a user wishes to access a system, a client side session cookie is set that enables them to pass through the Apache server.  The cookie is presented to the blacklist script, 'DNShijack.pm', and if it checks out to be valid the requst is passed to mod_proxy and handled approiately, the cookie is stripped out on it's way though so the destination webserver never sees it.  This is where the server side KEY is considered, so malicious users cannot amend the cookie to whitelist alternative domains too.  Now, when that cookie is set Apache will not log requests made to it that are blacklisted so privacy concerns should also be a non-issue.  The only things in the log you should see is the initial request where a user hits the page, and an entry in the error.log stating that the user has accepted the 'risk' in going to the site.

**N.B.** bear in mind that this system is ineffective against anything that directly accesses the IP address of a blacklisted domain, no DNS lookup, no blacklisting.  This sort of thing probably should be handled by your firewall.  So if the [hosts file](http://en.wikipedia.org/wiki/Hosts_file) is tweaked on the workstation its-self, then the user will not benefit from this type of system.  Alternatively you might want to look into my [Unsavoury IP Route Blackholing](route-blackholing) page to solve this.

## Interesting Projects

To customise the webpages the user sees all you need to do is amend '/var/local/dnshijack/templates/en/' (copy the directory and name it to the i18n language you use if you want to regionise the system) and edit the file to your hearts content; no need to restart Apache after changing this.

If you packet sniff on the network interface of the webserver and filter ports 53 and 80:

    # tcpdump -i bond0 -n -p host ids.example.com and not port 53 and not port 80

You will be able to catch all the 'strange' requests being made to the blacklisted domain, probably finding malware your AV is unable to.
