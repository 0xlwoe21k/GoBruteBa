package passive

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	alienvault2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/alienvault"
	anubis2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/anubis"
	archiveis2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/archiveis"
	binaryedge2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/binaryedge"
	bufferover2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/bufferover"
	censys2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/censys"
	certspotter2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/certspotter"
	chaos2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/chaos"
	commoncrawl2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/commoncrawl"
	crtsh2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/crtsh"
	dnsdb2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/dnsdb"
	dnsdumpster2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/dnsdumpster"
	github2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/github"
	hackertarget2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/hackertarget"
	intelx2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/intelx"
	passivetotal2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/passivetotal"
	rapiddns2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/rapiddns"
	recon2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/recon"
	riddler2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/riddler"
	robtex2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/robtex"
	securitytrails2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/securitytrails"
	shodan2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/shodan"
	sitedossier2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/sitedossier"
	sonarsearch2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/sonarsearch"
	spyse2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/spyse"
	sublist3r2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/sublist3r"
	threatbook2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/threatbook"
	threatcrowd2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/threatcrowd"
	threatminer2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/threatminer"
	virustotal2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/virustotal"
	waybackarchive2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/waybackarchive"
	zoomeye2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping/sources/zoomeye"
)

// DefaultSources contains the list of fast sources used by default.
var DefaultSources = []string{
	"alienvault",
	"anubis",
	"bufferover",
	"certspotter",
	"censys",
	"chaos",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"intelx",
	"passivetotal",
	"robtex",
	"riddler",
	"securitytrails",
	"shodan",
	"spyse",
	"sublist3r",
	"threatcrowd",
	"threatminer",
	"virustotal",
}

// DefaultRecursiveSources contains list of default recursive sources
var DefaultRecursiveSources = []string{
	"alienvault",
	"binaryedge",
	"bufferover",
	"certspotter",
	"crtsh",
	"dnsdumpster",
	"hackertarget",
	"passivetotal",
	"securitytrails",
	"sonarsearch",
	"sublist3r",
	"virustotal",
}

// DefaultAllSources contains list of all sources
var DefaultAllSources = []string{
	"alienvault",
	"anubis",
	"archiveis",
	"binaryedge",
	"bufferover",
	"censys",
	"certspotter",
	"chaos",
	"commoncrawl",
	"crtsh",
	"dnsdumpster",
	"dnsdb",
	"github",
	"hackertarget",
	"intelx",
	"passivetotal",
	"rapiddns",
	"riddler",
	"recon",
	"robtex",
	"securitytrails",
	"shodan",
	"sitedossier",
	"sonarsearch",
	"spyse",
	"sublist3r",
	"threatbook",
	"threatcrowd",
	"threatminer",
	"virustotal",
	"waybackarchive",
	"zoomeye",
}

// Agent is a struct for running passive subdomain enumeration
// against a given host. It wraps subscraping package and provides
// a layer to build upon.
type Agent struct {
	sources map[string]subscraping2.Source
}

// New creates a new agent for passive subdomain discovery
func New(sources, exclusions []string) *Agent {
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping2.Source)}

	agent.addSources(sources)
	agent.removeSources(exclusions)

	return agent
}

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "alienvault":
			a.sources[source] = &alienvault2.Source{}
		case "anubis":
			a.sources[source] = &anubis2.Source{}
		case "archiveis":
			a.sources[source] = &archiveis2.Source{}
		case "binaryedge":
			a.sources[source] = &binaryedge2.Source{}
		case "bufferover":
			a.sources[source] = &bufferover2.Source{}
		case "censys":
			a.sources[source] = &censys2.Source{}
		case "certspotter":
			a.sources[source] = &certspotter2.Source{}
		case "chaos":
			a.sources[source] = &chaos2.Source{}
		case "commoncrawl":
			a.sources[source] = &commoncrawl2.Source{}
		case "crtsh":
			a.sources[source] = &crtsh2.Source{}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster2.Source{}
		case "dnsdb":
			a.sources[source] = &dnsdb2.Source{}
		case "github":
			a.sources[source] = &github2.Source{}
		case "hackertarget":
			a.sources[source] = &hackertarget2.Source{}
		case "intelx":
			a.sources[source] = &intelx2.Source{}
		case "passivetotal":
			a.sources[source] = &passivetotal2.Source{}
		case "rapiddns":
			a.sources[source] = &rapiddns2.Source{}
		case "recon":
			a.sources[source] = &recon2.Source{}
		case "riddler":
			a.sources[source] = &riddler2.Source{}
		case "robtex":
			a.sources[source] = &robtex2.Source{}
		case "securitytrails":
			a.sources[source] = &securitytrails2.Source{}
		case "shodan":
			a.sources[source] = &shodan2.Source{}
		case "sitedossier":
			a.sources[source] = &sitedossier2.Source{}
		case "sonarsearch":
			a.sources[source] = &sonarsearch2.Source{}
		case "spyse":
			a.sources[source] = &spyse2.Source{}
		case "sublist3r":
			a.sources[source] = &sublist3r2.Source{}
		case "threatbook":
			a.sources[source] = &threatbook2.Source{}
		case "threatcrowd":
			a.sources[source] = &threatcrowd2.Source{}
		case "threatminer":
			a.sources[source] = &threatminer2.Source{}
		case "virustotal":
			a.sources[source] = &virustotal2.Source{}
		case "waybackarchive":
			a.sources[source] = &waybackarchive2.Source{}
		case "zoomeye":
			a.sources[source] = &zoomeye2.Source{}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
