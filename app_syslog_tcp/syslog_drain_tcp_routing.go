package apps

import (
	"fmt"
	"time"

	. "github.com/cloudfoundry/cf-acceptance-tests/cats_suite_helpers"
	"github.com/cloudfoundry/cf-acceptance-tests/tcp_routing"

	"github.com/cloudfoundry/cf-acceptance-tests/helpers/app_helpers"
	"github.com/cloudfoundry/cf-acceptance-tests/helpers/assets"
	logshelper "github.com/cloudfoundry/cf-acceptance-tests/helpers/logs"
	"github.com/cloudfoundry/cf-acceptance-tests/helpers/random_name"
	"github.com/cloudfoundry/cf-test-helpers/v2/cf"
	"github.com/cloudfoundry/cf-test-helpers/v2/workflowhelpers"
	. "github.com/onsi/ginkgo/v2"
	. "github.com/onsi/gomega"
	. "github.com/onsi/gomega/gbytes"
	. "github.com/onsi/gomega/gexec"
)

var _ = AppSyslogTcpDescribe("Syslog Drain over TCP (tcp-routing based)", func() {
	var logWriterAppName1 string
	var logWriterAppName2 string
	var domainName string
	var externalPort string
	var listenerAppName string
	var logs *Session
	var interrupt chan struct{}
	var serviceName string

	SkipOnK8s("Not yet supported")

	Describe("Syslog drains", func() {
		BeforeEach(func() {
			if !Config.GetIncludeTCPRouting() {
				Skip("No tcp routing active. Skipping corresponding syslog_drain test")
			}
			interrupt = make(chan struct{}, 1)

			domainName = fmt.Sprintf("tcp.%s", Config.GetAppsDomain())
			workflowhelpers.AsUser(TestSetup.AdminUserContext(), Config.DefaultTimeoutDuration(), func() {
				routerGroupOutput := string(cf.Cf("router-groups").Wait().Out.Contents())
				Expect(routerGroupOutput).To(
					MatchRegexp(fmt.Sprintf("%s\\s+tcp", tcp_routing.DefaultRouterGroupName)),
					fmt.Sprintf("Router group %s of type tcp doesn't exist", tcp_routing.DefaultRouterGroupName),
				)

				Expect(cf.Cf("create-shared-domain",
					domainName,
					"--router-group", tcp_routing.DefaultRouterGroupName,
				).Wait()).To(Exit())
			})
			serviceName = random_name.CATSRandomName("SVIN1")
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
			), Config.CfPushTimeoutDuration()).Should(Exit(0), "Failed to push app")

			externalPort = MapTCPRoute(listenerAppName, domainName)

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
			if !Config.GetIncludeTCPRouting() {
				Skip("No tcp routing active. Skipping corresponding syslog_drain test")
			}
			logs.Kill()
			close(interrupt)

			app_helpers.AppReport(logWriterAppName1)
			app_helpers.AppReport(logWriterAppName2)
			app_helpers.AppReport(listenerAppName)

			Eventually(cf.Cf("delete", logWriterAppName1, "-f", "-r")).Should(Exit(0), "Failed to delete app")
			Eventually(cf.Cf("delete", logWriterAppName2, "-f", "-r")).Should(Exit(0), "Failed to delete app")
			Eventually(cf.Cf("delete", listenerAppName, "-f", "-r")).Should(Exit(0), "Failed to delete app")
			if serviceName != "" {
				Eventually(cf.Cf("delete-service", serviceName, "-f")).Should(Exit(0), "Failed to delete service")
			}

			Eventually(cf.Cf("delete-orphaned-routes", "-f"), Config.CfPushTimeoutDuration()).Should(Exit(0), "Failed to delete orphaned routes")
		})

		It("forwards app messages to registered tcp-routing based syslog drains", func() {
			Eventually(cf.Cf("cups", serviceName, "-l", fmt.Sprintf("syslog://%s:%s", domainName, externalPort))).Should(Exit(0), "Failed to create syslog drain service")
			Eventually(cf.Cf("bind-service", logWriterAppName1, serviceName)).Should(Exit(0), "Failed to bind service")

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
