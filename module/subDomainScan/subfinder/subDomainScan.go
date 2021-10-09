package subfinder

import (
	runner2 "GoBruteBa/module/subDomainScan/subfinder/source/runner"
	"context"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"
)

func SubDomainScan(option *runner2.Options) {
	// Parse the command line flags and read config files
	options := runner2.ParseOptions(option)

	newRunner, err := runner2.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	err = newRunner.RunEnumeration(context.Background())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
