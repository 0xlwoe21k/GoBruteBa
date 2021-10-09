package runner

import (
	passive2 "GoBruteBa/module/subDomainScan/subfinder/source/passive"
	resolve2 "GoBruteBa/module/subDomainScan/subfinder/source/resolve"
	"github.com/projectdiscovery/gologger"
)

const Version = `2.4.8`

// showBanner is used to show the banner to the user
//func showBanner() {
//
//	gologger.Print().Msgf("Use with caution. You are responsible for your actions\n")
//	gologger.Print().Msgf("Developers assume no liability and are not responsible for any misuse or damage.\n")
//	gologger.Print().Msgf("By using subfinder, you also agree to the terms of the APIs used.\n\n")
//}

// normalRunTasks runs the normal startup tasks
func (options *Options) normalRunTasks() {
	configFile, err := UnmarshalRead(options.ConfigFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not read configuration file %s: %s\n", options.ConfigFile, err)
	}

	// If we have a different version of subfinder installed
	// previously, use the new iteration of config file.
	if configFile.Version != Version {
		configFile.Sources = passive2.DefaultSources
		configFile.AllSources = passive2.DefaultAllSources
		configFile.Recursive = passive2.DefaultRecursiveSources
		configFile.Version = Version

		err = configFile.MarshalWrite(options.ConfigFile)
		if err != nil {
			gologger.Fatal().Msgf("Could not update configuration file to %s: %s\n", options.ConfigFile, err)
		}
	}
	options.YAMLConfig = configFile
}

// firstRunTasks runs some housekeeping tasks done
// when the program is ran for the first time
func (options *Options) firstRunTasks() {
	// Create the configuration file and display information
	// about it to the user.
	config := ConfigFile{
		// Use the default list of resolvers by marshaling it to the config
		Resolvers: resolve2.DefaultResolvers,
		// Use the default list of passive sources
		Sources: passive2.DefaultSources,
		// Use the default list of all passive sources
		AllSources: passive2.DefaultAllSources,
		// Use the default list of recursive sources
		Recursive: passive2.DefaultRecursiveSources,
	}

	err := config.MarshalWrite(options.ConfigFile)
	if err != nil {
		gologger.Fatal().Msgf("Could not write configuration file to %s: %s\n", options.ConfigFile, err)
	}
	options.YAMLConfig = config

	gologger.Info().Msgf("Configuration file saved to %s\n", options.ConfigFile)
}
