package passive

import (
	subscraping2 "GoBruteBa/module/subDomainScan/subfinder/source/subscraping"
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/projectdiscovery/gologger"
)

// EnumerateSubdomains enumerates all the subdomains for a given domain
func (a *Agent) EnumerateSubdomains(domain string, keys *subscraping2.Keys, timeout int, maxEnumTime time.Duration) chan subscraping2.Result {
	results := make(chan subscraping2.Result)

	go func() {
		session, err := subscraping2.NewSession(domain, keys, timeout)
		if err != nil {
			results <- subscraping2.Result{Type: subscraping2.Error, Error: fmt.Errorf("could not init passive session for %s: %s", domain, err)}
		}

		ctx, cancel := context.WithTimeout(context.Background(), maxEnumTime)

		timeTaken := make(map[string]string)
		timeTakenMutex := &sync.Mutex{}

		wg := &sync.WaitGroup{}
		// Run each source in parallel on the target domain
		for source, runner := range a.sources {
			wg.Add(1)

			now := time.Now()
			go func(source string, runner subscraping2.Source) {
				for resp := range runner.Run(ctx, domain, session) {
					results <- resp
				}

				duration := time.Since(now)
				timeTakenMutex.Lock()
				timeTaken[source] = fmt.Sprintf("Source took %s for enumeration\n", duration)
				timeTakenMutex.Unlock()

				wg.Done()
			}(source, runner)
		}
		wg.Wait()

		for source, data := range timeTaken {
			gologger.Verbose().Label(source).Msg(data)
		}

		close(results)
		cancel()
	}()

	return results
}
