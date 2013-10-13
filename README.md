wtn
===

What The Net - connectivity issue diagnosis

 * Checks \[ICMP and DNS\] connectivity to quickly diagnose connectivity issues, i.e. am i connected at all, or is there some issue in my network (e.g. DNS).
 * also provides some basic information such as what the Gateway address is on the default route, and which IP address is used on that default route.
 * In verbose mode wtn shows traceroute-type information.

Installation note: wtn uses `setuid` to send packets, so it needs to be owned by root and have the `setuid` permission set. If this doesn't mean anything to you, just run `./install.sh`

Options:

	` wtn` [options]
	  -d="www.google.com": public target for DNS check
	  -h=false: Show this help
	  -t="8.8.8.8": public target for Traceroute test
	  -v=false: Print details

This is just an early version.
In future wtn should support different scenarios & topologies such as VPNs, bonding, multiple networks, etc.
