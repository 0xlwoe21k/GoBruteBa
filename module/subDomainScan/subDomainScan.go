package subDomainScan

import (
	"context"
	_ "github.com/projectdiscovery/fdmax/autofdmax"
	"github.com/projectdiscovery/gologger"

	"GoBruteBa/module/subDomainScan/source/runner"
)

func SubDomainScan(option *runner.Options) {
	// Parse the command line flags and read config files
	options := runner.ParseOptions(option)

	newRunner, err := runner.NewRunner(options)
	if err != nil {
		gologger.Fatal().Msgf("Could not create runner: %s\n", err)
	}

	err = newRunner.RunEnumeration(context.Background())
	if err != nil {
		gologger.Fatal().Msgf("Could not run enumeration: %s\n", err)
	}
}
