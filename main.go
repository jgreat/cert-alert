package main

import (
	"context"
	"crypto/x509"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/slack-go/slack"
)

var version string = ""

type certificateDates struct {
	expirationDate  time.Time
	renewBeforeDate time.Time
}

type cliGlobal struct {
	slackToken  *string
	renewBefore *string
	subjects    *string
	address     *string
	version     *bool
	debug       *bool
}

func main() {
	flags := &cliGlobal{}
	flags.slackToken = flag.String("slack-token", os.Getenv("SLACK_TOKEN"), "")
	flags.renewBefore = flag.String("renew-before", os.Getenv("RENEW_BEFORE"), "")
	flags.subjects = flag.String("subjects", os.Getenv("SUBJECTS"), "")
	flags.address = flag.String("address", os.Getenv("ADDRESS"), "")
	flags.version = flag.Bool("version", false, "")
	flags.debug = flag.Bool("debug", false, "")

	flag.CommandLine.Usage = help
	flag.Parse()

	if *flags.version {
		fmt.Printf("version: %v\n", version)
		os.Exit(0)
	}
	if *flags.subjects == "" {
		help()
		fmt.Println("Error: --subjects or $SUBJECTS required")
		os.Exit(1)
	}
	if *flags.renewBefore == "" {
		*flags.renewBefore = "30"
	}

	// Default to INFO level logging
	logLevel := &slog.LevelVar{}

	// Set log level to DEBUG if --debug flag is set
	if *flags.debug {
		logLevel.Set(slog.LevelDebug)
	}

	// Set up logger
	logOpts := &slog.HandlerOptions{
		Level: logLevel,
	}
	logger := slog.New(slog.NewJSONHandler(os.Stdout, logOpts))
	slog.SetDefault(logger)

	// Run the app
	err := run(flags)
	if err != nil {
		slog.Error(fmt.Sprintf("%v", err))
		os.Exit(1)
	}
}

func help() {
	fmt.Printf("Usage: %v --subjects=SUBJECTS,...\n", os.Args[0])
	fmt.Println("")
	fmt.Println("Connect to websites to see if certs are about to expire.")
	fmt.Println("Send alerts to slack if --slack-token is defined.")
	fmt.Println("")
	fmt.Println("Flags:")
	fmt.Println("  --help                     Show this message")
	fmt.Println("  --slack-token=STRING       Token for slack. Will post to all channels @cert-alert is invited to. ($SLACK_TOKEN)")
	fmt.Println("  --renew-before=30          Renew days before cert expiration ($RENEW_BEFORE)")
	fmt.Println("  --subjects=SUBJECTS,...    List of certificate subjects (hostnames) to check. ($SUBJECTS)")
	fmt.Println("  --address=ADDRESS          Use IP:PORT address listed instead of DNS lookup to connect to server ($ADDRESS)")
	fmt.Println("  --debug                    Enable debug logging")
	fmt.Println("  --version                  Show version and exit")
	fmt.Println("")
	fmt.Printf("Version: %v\n", version)
	fmt.Println("")
}

// Run DefaultCmd - Default command for Kong CLI framework.
func run(global *cliGlobal) error {

	slog.Debug("Checking certificates for expiration")
	slackMessageAttachments := []slack.Attachment{}

	// break down subjects
	subjects := strings.Split(*global.subjects, ",")

	for _, subject := range subjects {
		slog.Debug(fmt.Sprintf("Checking %v", subject))
		certFound := false
		subjectLink := fmt.Sprintf("https://%v", subject)

		// drop the first element from the domain name to get the base domain and add * to the front.
		subjectSplit := strings.Split(subject, ".")[1:]
		subjectSplit = slices.Insert(subjectSplit, 0, "*")
		subjectStarDomain := strings.Join(subjectSplit, ".")

		// Create a custom HTTP client if the address flag is provided
		var client *http.Client
		if *global.address != "" {
			transport := createCustomTransport(*global.address)
			doNotFollowRedirects := func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			}
			client = &http.Client{CheckRedirect: doNotFollowRedirects, Transport: transport}
		} else {
			client = &http.Client{}
		}

		resp, err := client.Head(subjectLink)
		if err != nil {
			slog.Error(fmt.Sprintf("%v", err))
			continue
		}
		defer resp.Body.Close()

		certs := resp.TLS.PeerCertificates
		slog.Debug(fmt.Sprintf("Found %v certificates", len(certs)))

		for _, cert := range certs {
			pastDue := false
			certDates := &certificateDates{}
			renewBefore, err := strconv.Atoi(*global.renewBefore)
			if err != nil {
				return err
			}

			slog.Debug(fmt.Sprintf("CommonName %v - DNSNames %v", cert.Subject.CommonName, cert.DNSNames))

			if subject == cert.Subject.CommonName {
				pastDue, certDates = isAfterRenewDate(cert, renewBefore)
				certFound = true
			} else if contains(cert.DNSNames, subject) {
				pastDue, certDates = isAfterRenewDate(cert, renewBefore)
				certFound = true
			} else if contains(cert.DNSNames, subjectStarDomain) {
				pastDue, certDates = isAfterRenewDate(cert, renewBefore)
				certFound = true
			} else {
				slog.Debug("Subject not found, probably chain cert")
				continue
			}

			if pastDue {
				slog.Info(
					"cert info found",
					"status", "PastDue",
					"subject", subject,
					"expires_on", fmt.Sprintf("%v", cert.NotAfter),
					"renew_before", fmt.Sprintf("%v", certDates.renewBeforeDate),
				)
				attachment := slack.Attachment{
					Title:     subject,
					TitleLink: subjectLink,
					Pretext:   fmt.Sprintf(":warning: TLS cert for %v will expire in less than %v days.", subject, renewBefore),
					Color:     "danger",
					Fields: []slack.AttachmentField{
						{
							Title: "Certificate Expires",
							Value: certDates.expirationDate.UTC().Format("Mon Jan 2 15:04:05 MST 2006"),
						},
						{
							Title: "Certificate Renew By",
							Value: certDates.renewBeforeDate.UTC().Format("Mon Jan 2 15:04:05 MST 2006"),
						},
						{
							Title: "Certificate Issued By",
							Value: cert.Issuer.CommonName,
						},
						{
							Title: "Subject Common Name",
							Value: cert.Subject.CommonName,
						},
						{
							Title: "Subject Alternative Names",
							Value: strings.Join(cert.DNSNames, "\n"),
						},
					},
				}
				slackMessageAttachments = append(slackMessageAttachments, attachment)
			} else {
				slog.Info(
					"cert info found",
					"status", "OK",
					"subject", subject,
					"expires_on", fmt.Sprintf("%v", cert.NotAfter),
					"renew_before", fmt.Sprintf("%v", certDates.renewBeforeDate),
				)
			}
		}

		if !certFound {
			attachment := slack.Attachment{
				Title:     subject,
				TitleLink: subjectLink,
				Pretext:   fmt.Sprintf(":warning: TLS cert for %v was not found", subject),
				Color:     "danger",
			}
			slackMessageAttachments = append(slackMessageAttachments, attachment)
			slog.Error(
				"cert info not found",
				"status", "NotFound",
				"subject", subject,
			)
		}
	}

	if *global.slackToken != "" {
		err := sendSlackMessage(*global.slackToken, slackMessageAttachments)
		if err != nil {
			return err
		}
	}
	return nil
}

func contains(s []string, item string) bool {
	for _, a := range s {
		if a == item {
			return true
		}
	}
	return false
}

// isAfterRenewDate - returns false if today is before the renew date (good)
//
//	true if after renew date (bad)
func isAfterRenewDate(cert *x509.Certificate, renewBefore int) (bool, *certificateDates) {
	now := time.Now()
	renewBeforeDate := cert.NotAfter.AddDate(0, 0, -renewBefore)
	dates := &certificateDates{
		expirationDate:  cert.NotAfter,
		renewBeforeDate: renewBeforeDate,
	}

	if now.After(renewBeforeDate) {
		return true, dates
	}
	return false, dates
}

// sendSlackMessage - Sends message attachments to all channels @cert-alert is subscribed to.
func sendSlackMessage(token string, message []slack.Attachment) error {
	if len(message) > 0 {
		api := slack.New(token, slack.OptionDebug(true))

		conversationParameters := &slack.GetConversationsParameters{
			Limit:           1000,
			ExcludeArchived: true,
			Types:           []string{"public_channel", "private_channel", "mpim", "im"},
		}
		channels, _, err := api.GetConversations(conversationParameters)
		if err != nil {
			return fmt.Errorf("ERROR: Slack GetConversations: %v", err)
		}

		for _, c := range channels {
			if c.IsMember {
				channelID, timestamp, err := api.PostMessage(c.ID, slack.MsgOptionText("", false), slack.MsgOptionAttachments(message...))
				if err != nil {
					return fmt.Errorf("ERROR: Slack PostMessage: %v", err)
				}
				slog.Info(fmt.Sprintf("Message successfully sent to channel %s at %s", channelID, timestamp))
			}
		}
	}
	return nil
}

func createCustomTransport(address string) *http.Transport {
	dialer := &net.Dialer{}
	return &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			// Use the provided address instead of resolving the hostname
			return dialer.DialContext(ctx, network, address)
		},
	}
}
