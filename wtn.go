package main

import (
	"flag"
	"fmt"
	"log"
	"syscall"
	"net"
	"os"
	"github.com/laher/wtn/trace"
)

func main() {
	call := os.Args
	flagSet := flag.NewFlagSet("wtn", flag.ContinueOnError)
	targetFlag := flagSet.String("t", "8.8.8.8", "public target for Traceroute test")
	dnsTargetFlag := flagSet.String("d", "www.google.com", "public target for DNS check")
	verboseFlag := flagSet.Bool("v", false, "Print details")
	helpFlag := flagSet.Bool("h", false, "Show this help")
	err := flagSet.Parse(call[1:])
	if err != nil {
		fmt.Printf("Error: %v\n", err)
		return
	}
	if *helpFlag {
		println("`wtn` [options]")
		flagSet.PrintDefaults()
		return
	}
	err = syscall.Setuid(0)
	if err != nil {
		//TODO provide some alternative if setuid fails
		log.Printf("WARNING: Setuid failed - Unix users should chown (root) & chmod (+s) this executable accordingly - see 'install.sh'. ... %v", err)
	}

	verbose := *verboseFlag
	target := *targetFlag
	dnsTarget := *dnsTargetFlag
	if verbose {
		log.Printf("Tracerouting to "+target+" ...")
	}
	hops := 1
	maxHops := 30
	complete := false
	firstHop := ""
	myIp := ""
	for complete == false && hops < maxHops {
		rh := trace.Hop("ip4:icmp", "0.0.0.0", target, hops)
		from := rh.Src.String()
		if hops == 1 {
			firstHop = from
			myIp = rh.Dst.String()
			fmt.Printf("My address:\t%s\n", myIp)
			fmt.Printf("Gateway IP:\t%s\n", firstHop)
		}
		if verbose {
			log.Printf(" Hop %d: %s", hops, from)
		}
		complete = from == target
		hops++
	}
	if complete {
		fmt.Printf("Pub internet:\tOK (%s accessible)\n", target)
	} else {
		fmt.Printf("Pub internet:\tERROR (%s NOT accesible)\n", target)
	}
	addrs, err := net.LookupHost(dnsTarget)
	if err != nil {
		fmt.Printf("DNS lookup:\tERROR (%v)\n", err)
	} else {
		if verbose {
			log.Printf("DNS lookup result for %s: %v", dnsTarget, addrs)
		}
		fmt.Printf("DNS lookup:\tOK (for %s)\n", dnsTarget)
	}
	if !complete || err != nil {
		os.Exit(1)
	}
}
