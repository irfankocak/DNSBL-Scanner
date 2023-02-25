package main

import (
	"bufio"
	"fmt"
	"net"
	"os"
	"strings"
	"sync"

	"github.com/common-nighthawk/go-figure"
	"github.com/fatih/color"
)

// DNSBL maps the name of a DNSBL to its domain name.
var DNSBL = map[string]string{
	"Composite Blocking":          "cbl.abuseat.org",
	"Barracuda Reputation Block":  "b.barracudacentral.org",
	"DNSBL SPFBL":                 "dnsbl.spfbl.net",
	"URIBL red":                   "red.uribl.com",
	"URIBL grey":                  "grey.uribl.com",
	"URIBL black":                 "black.uribl.com",
	"URIBL multi":                 "multi.uribl.com",
	"DroneBL":                     "dnsbl.dronebl.org",
	"abuse.ro RBL":                "rbl.abuse.ro",
	"anonmails.de DNSBL":          "spam.dnsbl.anonmails.de",
	"JIPPG`s Relay Blackhole":     "mail-abuse.blacklist.jippg.org",
	"BlockedServers":              "rbl.blockedservers.com",
	"BlockList.de":                "bl.blocklist.de",
	"Blog Spam Blacklist":         "list.blogspambl.com",
	"Calivent DNSBL":              "dnsbl.calivent.com.pe",
	"IBM DNS Blacklist":           "dnsbl.cobion.com",
	"Bogon":                       "bogons.cymru.com",
	"Torexit":                     "torexit.dan.me.uk",
	"Servicios RBL":               "rbl.dns-servicios.com",
	"DrMX":                        "bl.drmx.org",
	"EFnet - TOR":                 "rbl.efnetrbl.org",
	"SpamSources RBL":             "spamsources.fabel.dk",
	"ZapBL DNSRBL":                "dnsbl.zapbl.net",
	"Blog Spam Blocklist":         "bsb.empty.us",
	"Spam Lookup RBL":             "bsb.spamlookup.net",
	"Spam Eating Monkey":          "fresh.spameatingmonkey.net",
	"SURBL multi":                 "multi.surbl.org",
	"Woodys SMTP Blacklist URIBL": "uri.blacklist.woody.ch",
	"Dynip Rothen List":           "dynip.rothen.com",
	"ZoneEdit deny DNS ":          "ban.zebl.zoneedit.com",
	"The Day Old Bread List":      "dob.sibl.support-intelligence.net",
	"Rymshos RHSBL":               "rhsbl.rymsho.ru",
	"abuse.ro URI RBL":            "uribl.abuse.ro",
	"Sorbs DNSBL":                 "dnsbl.sorbs.net",
	"Zen DNSBL":                   "zen.spamhaus.org",
	"Spamcop BL":                  "bl.spamcop.net",
	"UceProtect DNSBL":            "dnsbl-1.uceprotect.net",
	"Surriel PSBL":                "psbl.surriel.com",
	"SpamHaus DNSBL":              "dnsbl.sbl.spamhaus.org",
	"SpamHaus PBL":                "pbl.spamhaus.org",
	"SpamHaus SBL":                "sbl-xbl.spamhaus.org",
	"SpamHaus XBL":                "xbl.spamhaus.org",
	"SORBS Spam":                  "spam.dnsbl.sorbs.net",
	"SpamRATS":                    "zen.spamrats.com",
	"SORBS Escalations":           "escalations.dnsbl.sorbs.net",
	"SORBS Safe":                  "safe.dnsbl.sorbs.net",
	"UCEPROTECT Level 1":          "dnsbl-1.uceprotect.net",
	"UCEPROTECT Level 2":          "dnsbl-2.uceprotect.net",
	"UCEPROTECT Level 3":          "dnsbl-3.uceprotect.net",
	"UCEPROTECT Level 4":          "dnsbl-4.uceprotect.net",
	"Team Cymru":                  "bogons.cymru.com",
	"Backscatterer":               "ips.backscatterer.org",
	"Abuseat":                     "truncate.gbudb.net",
	"Invaluement":                 "ubl.unsubscore.com",
	"Mailspike":                   "bl.mailspike.net",
	"Sorbs Zombie":                "zombie.dnsbl.sorbs.net",
	"Mail Spike":                  "z.mailspike.net",
	"Worm RBL":                    "wormrbl.imp.ch",
	"RBL.jp":                      "virus.rbl.jp",
	"Lash Hack UBL":               "ubl.lashback.com",
	"Abuse.ch":                    "spam.abuse.ch",
	"Spfbl DNSBL":                 "dnsbl.spfbl.net",
	"S5h ALL":                     "all.s5h.net",
	"Inps DNSBL":                  "dnsbl.inps.de",
	"Korea Services":              "korea.services.net",
	"0Spam Project":               "bl.0spam.org",
	"0spam DBL":                   "url.0spam.org",
	"Anonmails":                   "spam.dnsbl.anonmails.de",
	"JustSpam":                    "dnsbl.justspam.org",
}

// checkDNSBL checks if an IP address is in a DNS blacklist.
func checkDNSBL(ip net.IP, bl string) (bool, error) {
	// Reverse the IP address and append the DNSBL domain name.
	ipStr := reverseIP(ip)
	lookup := fmt.Sprintf("%s.%s", ipStr, bl)

	// Perform the DNS query.
	_, err := net.LookupHost(lookup)
	if err != nil {
		if dnsErr, ok := err.(*net.DNSError); ok {
			// If the error is a "no such host" error, the IP address is not in the DNS blacklist.
			if dnsErr.Err == "no such host" {
				return false, nil
			}
			return false, dnsErr
		}
		return false, err
	}
	return true, nil
}

// reverseIP reverses the order of bytes in an IP address.
func reverseIP(ip net.IP) string {
	ipStr := ip.String()
	parts := strings.Split(ipStr, ".")
	for i, j := 0, len(parts)-1; i < j; i, j = i+1, j-1 {
		parts[i], parts[j] = parts[j], parts[i]
	}
	return strings.Join(parts, ".")
}

func main() {

	myFigure := figure.NewColorFigure("DNSBL Scanner", "doom", "cyan", true)
	myFigure.Print()

	scanner := bufio.NewScanner(os.Stdin)

	for {
		fmt.Print("\nEnter an IP address or domain name (type 'exit' to quit): ")
		if !scanner.Scan() {
			break
		}
		input := strings.TrimSpace(scanner.Text())
		if input == "exit" {
			color.Yellow("\nExiting program...")
			return
		}

		// Look up the IP address for the input string.
		ipOrDomain := strings.TrimSpace(scanner.Text())
		ip := net.ParseIP(ipOrDomain)
		if ip == nil {
			ips, err := net.LookupIP(ipOrDomain)
			if err != nil {
				color.Red("Error: %s\n", err.Error())
				continue
			}
			ip = ips[0]
			color.Yellow("\nResolved IP address: %s\n\n", ip.String())
		} else {
			color.Yellow("\nResolved IP address: %s\n\n", ip.String())
		}

		// Check the IP address against each DNSBL.
		var wg sync.WaitGroup
		for shortName, url := range DNSBL {
			wg.Add(1)
			go func(shortName, url string) {
				defer wg.Done()
				result, err := checkDNSBL(ip, url)
				if err != nil {
					color.Red("Error checking %s: %s\n", shortName, err.Error())
				} else {
					var resultStr strings.Builder

					resultStr.WriteString(fmt.Sprintf(color.HiBlueString("IP address: ") + ip.String() + "  "))
					resultStr.WriteString(fmt.Sprintf(color.HiBlueString("Blacklist DB: ") + shortName))

					// Calculate the padding needed for status field
					padding := 30 - len(shortName)
					if padding > 0 {
						resultStr.WriteString(strings.Repeat(" ", padding))
					}

					resultStr.WriteString(fmt.Sprintf(color.HiBlueString("Status: ")))
					if result {
						resultStr.WriteString(color.HiRedString("Listed	"))
					} else {
						resultStr.WriteString(color.GreenString("Not listed	"))
					}

					// Print the result string
					fmt.Println(resultStr.String())
				}
			}(shortName, url)
		}
		wg.Wait()
	}
}
