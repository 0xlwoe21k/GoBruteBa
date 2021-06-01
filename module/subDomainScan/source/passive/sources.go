package passive

import (
	"GoBruteBa/module/subDomainScan/source/subscraping"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/alienvault"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/anubis"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/archiveis"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/binaryedge"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/bufferover"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/censys"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/certspotter"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/chaos"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/commoncrawl"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/crtsh"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/dnsdb"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/dnsdumpster"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/github"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/hackertarget"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/intelx"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/passivetotal"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/rapiddns"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/recon"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/riddler"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/robtex"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/securitytrails"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/shodan"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/sitedossier"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/sonarsearch"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/spyse"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/sublist3r"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/threatbook"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/threatcrowd"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/threatminer"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/virustotal"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/waybackarchive"
	"GoBruteBa/module/subDomainScan/source/subscraping/sources/zoomeye"
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
	sources map[string]subscraping.Source
}

// New creates a new agent for passive subdomain discovery
func New(sources, exclusions []string) *Agent {
	// Create the agent, insert the sources and remove the excluded sources
	agent := &Agent{sources: make(map[string]subscraping.Source)}

	agent.addSources(sources)
	agent.removeSources(exclusions)

	return agent
}

// addSources adds the given list of sources to the source array
func (a *Agent) addSources(sources []string) {
	for _, source := range sources {
		switch source {
		case "alienvault":
			a.sources[source] = &alienvault.Source{}
		case "anubis":
			a.sources[source] = &anubis.Source{}
		case "archiveis":
			a.sources[source] = &archiveis.Source{}
		case "binaryedge":
			a.sources[source] = &binaryedge.Source{}
		case "bufferover":
			a.sources[source] = &bufferover.Source{}
		case "censys":
			a.sources[source] = &censys.Source{}
		case "certspotter":
			a.sources[source] = &certspotter.Source{}
		case "chaos":
			a.sources[source] = &chaos.Source{}
		case "commoncrawl":
			a.sources[source] = &commoncrawl.Source{}
		case "crtsh":
			a.sources[source] = &crtsh.Source{}
		case "dnsdumpster":
			a.sources[source] = &dnsdumpster.Source{}
		case "dnsdb":
			a.sources[source] = &dnsdb.Source{}
		case "github":
			a.sources[source] = &github.Source{}
		case "hackertarget":
			a.sources[source] = &hackertarget.Source{}
		case "intelx":
			a.sources[source] = &intelx.Source{}
		case "passivetotal":
			a.sources[source] = &passivetotal.Source{}
		case "rapiddns":
			a.sources[source] = &rapiddns.Source{}
		case "recon":
			a.sources[source] = &recon.Source{}
		case "riddler":
			a.sources[source] = &riddler.Source{}
		case "robtex":
			a.sources[source] = &robtex.Source{}
		case "securitytrails":
			a.sources[source] = &securitytrails.Source{}
		case "shodan":
			a.sources[source] = &shodan.Source{}
		case "sitedossier":
			a.sources[source] = &sitedossier.Source{}
		case "sonarsearch":
			a.sources[source] = &sonarsearch.Source{}
		case "spyse":
			a.sources[source] = &spyse.Source{}
		case "sublist3r":
			a.sources[source] = &sublist3r.Source{}
		case "threatbook":
			a.sources[source] = &threatbook.Source{}
		case "threatcrowd":
			a.sources[source] = &threatcrowd.Source{}
		case "threatminer":
			a.sources[source] = &threatminer.Source{}
		case "virustotal":
			a.sources[source] = &virustotal.Source{}
		case "waybackarchive":
			a.sources[source] = &waybackarchive.Source{}
		case "zoomeye":
			a.sources[source] = &zoomeye.Source{}
		}
	}
}

// removeSources deletes the given sources from the source map
func (a *Agent) removeSources(sources []string) {
	for _, source := range sources {
		delete(a.sources, source)
	}
}
