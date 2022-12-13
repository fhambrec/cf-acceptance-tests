package apps

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strconv"
	"time"

	. "github.com/cloudfoundry/cf-acceptance-tests/cats_suite_helpers"

	"github.com/cloudfoundry/cf-acceptance-tests/helpers/app_helpers"
	"github.com/cloudfoundry/cf-acceptance-tests/helpers/assets"
	logshelper "github.com/cloudfoundry/cf-acceptance-tests/helpers/logs"
	"github.com/cloudfoundry/cf-acceptance-tests/helpers/random_name"
	"github.com/cloudfoundry/cf-test-helpers/v2/cf"
	"github.com/cloudfoundry/cf-test-helpers/v2/helpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

const numberOfListenerApps = 2

type Credentials struct {
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

var _ = AppSyslogTcpDescribe("Syslog Drain over TCP (ip based)", func() {
	var logWriterAppName1 string
	var logWriterAppName2 string
	var listenerAppName string
	var logs *Session
	var interrupt chan struct{}
	var serviceNames []string

	SkipOnK8s("Not yet supported")

	Describe("Syslog drains", func() {
		BeforeEach(func() {
			if Config.GetIncludeTCPRouting() {
				Skip("tcp routing active. Skipping ip based syslog_drain test")
			}
			interrupt = make(chan struct{}, 1)
			serviceNames = []string{
				random_name.CATSRandomName("SVIN1"),
				random_name.CATSRandomName("SVIN-INT1"),
				random_name.CATSRandomName("SVIN2"),
				random_name.CATSRandomName("SVIN-INT2"),
			}
			listenerAppName = random_name.CATSRandomName("APP-SYSLOG-LISTENER")
			logWriterAppName1 = random_name.CATSRandomName("APP-FIRST-LOG-WRITER")
			logWriterAppName2 = random_name.CATSRandomName("APP-SECOND-LOG-WRITER")

			Eventually(cf.Cf(
				"push",
				listenerAppName,
				"--health-check-type", "port",
				"-b", Config.GetGoBuildpackName(),
				"-m", DEFAULT_MEMORY_LIMIT,
				"-p", assets.NewAssets().SyslogDrainListener,
				"-f", assets.NewAssets().SyslogDrainListener+"/manifest.yml",
				"-i",
				strconv.Itoa(numberOfListenerApps),
			), Config.CfPushTimeoutDuration()).Should(Exit(0), "Failed to push app")

			Eventually(cf.Cf(
				"push",
				logWriterAppName1,
				"-b", Config.GetRubyBuildpackName(),
				"-m", DEFAULT_MEMORY_LIMIT,
				"-p", assets.NewAssets().RubySimple,
			), Config.CfPushTimeoutDuration()).Should(Exit(0), "Failed to push app")

			Eventually(cf.Cf(
				"push",
				logWriterAppName2,
				"-b", Config.GetRubyBuildpackName(),
				"-m", DEFAULT_MEMORY_LIMIT,
				"-p", assets.NewAssets().RubySimple,
			), Config.CfPushTimeoutDuration()).Should(Exit(0), "Failed to push app")
		})

		AfterEach(func() {
			if Config.GetIncludeTCPRouting() {
				Skip("tcp routing active. Skipping ip based syslog_drain test")
			}
			logs.Kill()
			close(interrupt)

			app_helpers.AppReport(logWriterAppName1)
			app_helpers.AppReport(logWriterAppName2)
			app_helpers.AppReport(listenerAppName)

			Eventually(cf.Cf("delete", logWriterAppName1, "-f", "-r")).Should(Exit(0), "Failed to delete app")
			Eventually(cf.Cf("delete", logWriterAppName2, "-f", "-r")).Should(Exit(0), "Failed to delete app")
			Eventually(cf.Cf("delete", listenerAppName, "-f", "-r")).Should(Exit(0), "Failed to delete app")
			for _, serviceName := range serviceNames {
				if serviceName != "" {
					Eventually(cf.Cf("delete-service", serviceName, "-f")).Should(Exit(0), "Failed to delete service")
				}
			}

			Eventually(cf.Cf("delete-orphaned-routes", "-f"), Config.CfPushTimeoutDuration()).Should(Exit(0), "Failed to delete orphaned routes")
		})

		It("forwards app messages to registered IP based syslog drains", func() {
			cert := Config.GetAppSyslogTcpClientCert()
			key := Config.GetAppSyslogTcpClientKey()
			credentials, err := json.Marshal(Credentials{Cert: cert, Key: key})
			if err != nil {
				panic(err)
			}

			// The syslog drains return two IP addresses: external & internal.
			// On a vanilla environment, apps can connect through the syslog service
			// to the external IP (Diego cell address and external port) of the drain
			// container.
			// On NSX-T, apps cannot connect to the external IP, but they can connect
			// to the internal IP (container IP and port 8080).
			for i, address := range getSyslogDrainAddresses(listenerAppName) {
				var syslogDrainURL string
				if Config.GetRequireProxiedAppTraffic() {
					syslogDrainURL = "syslog-tls://" + address
				} else {
					syslogDrainURL = "syslog://" + address
				}

				if cert == "" || key == "" {
					Eventually(cf.Cf("cups", serviceNames[i], "-l", syslogDrainURL)).Should(Exit(0), "Failed to create syslog drain service")
				} else {
					Eventually(cf.Cf("cups", serviceNames[i], "-l", syslogDrainURL, "-p", string(credentials))).Should(Exit(0), "Failed to create syslog drain service")
				}
				Eventually(cf.Cf("bind-service", logWriterAppName1, serviceNames[i])).Should(Exit(0), "Failed to bind service")
				// We don't need to restage, because syslog service bindings don't change the app's environment variables
			}

			randomMessage1 := random_name.CATSRandomName("RANDOM-MESSAGE-A")
			randomMessage2 := random_name.CATSRandomName("RANDOM-MESSAGE-B")

			logs = logshelper.Follow(listenerAppName)

			// Have apps emit logs.
			go writeLogsUntilInterrupted(interrupt, randomMessage1, logWriterAppName1)
			go writeLogsUntilInterrupted(interrupt, randomMessage2, logWriterAppName2)
			Eventually(logs, Config.DefaultTimeoutDuration()+2*time.Minute).Should(Say(randomMessage1))

			Consistently(logs, 10).ShouldNot(Say(randomMessage2))
		})
	})
})

func getSyslogDrainAddresses(appName string) []string {
	var addresses []string
	searchPatterns := []string{"CF_INSTANCE_INTERNAL_IP", "CF_INSTANCE_IP", "CF_INSTANCE_PORTS"}
	var regexMatches = make(map[string]string)
	var internalPort, externalPort uint16

	for i := 0; i < numberOfListenerApps; i++ {
		Eventually(func() []string {
			var appEnvironment = cf.Cf("ssh", appName, "-c env", "-i", strconv.Itoa(i)).Wait().Out.Contents()

			for _, pattern := range searchPatterns {
				expression, err := regexp.Compile(pattern + "=(.*)")
				Expect(err).NotTo(HaveOccurred())
				regexMatches[pattern] = string(expression.FindSubmatch(appEnvironment)[1])
			}

			internalPort, externalPort = parseInstancePorts([]byte(regexMatches["CF_INSTANCE_PORTS"]))

			internalAddress := fmt.Sprintf("%s:%d", regexMatches["CF_INSTANCE_INTERNAL_IP"], internalPort)
			externalAddress := fmt.Sprintf("%s:%d", regexMatches["CF_INSTANCE_IP"], externalPort)
			addresses = append(addresses, externalAddress)
			addresses = append(addresses, internalAddress)

			return []string{externalAddress, internalAddress}
		}).Should(Not(BeNil()))
	}

	return addresses
}

func parseInstancePorts(instancePorts []byte) (uint16, uint16) {
	var internalPort uint16 = 8080
	var externalPort uint16

	var ports []struct {
		External         uint16 `json:"external"`
		ExternalTLSProxy uint16 `json:"external_tls_proxy"`
	}

	err := json.Unmarshal(instancePorts, &ports)

	if err != nil {
		fmt.Printf("Cannot unmarshal CF_INSTANCE_PORTS: %s", err)
		os.Exit(1)
	}

	if len(ports) <= 0 {
		fmt.Printf("CF_INSTANCE_PORTS is empty")
		os.Exit(1)
	}

	externalPort = ports[0].External
	if externalPort == 0 {
		externalPort = ports[0].ExternalTLSProxy
	}

	return internalPort, externalPort
}

func writeLogsUntilInterrupted(interrupt chan struct{}, randomMessage string, logWriterAppName string) {
	defer GinkgoRecover()
	for {
		select {
		case <-interrupt:
			return
		default:
			helpers.CurlAppWithTimeout(Config, logWriterAppName, "/log/"+randomMessage, Config.DefaultTimeoutDuration())
			time.Sleep(3 * time.Second)
		}
	}
}
