package main

import (
	"crypto/x509"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
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
	version     *bool
}

func main() {
	flags := &cliGlobal{}
	flags.slackToken = flag.String("slack-token", os.Getenv("SLACK_TOKEN"), "")
	flags.renewBefore = flag.String("renew-before", os.Getenv("RENEW_BEFORE"), "")
	flags.subjects = flag.String("subjects", os.Getenv("SUBJECTS"), "")
	flags.version = flag.Bool("version", false, "")

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

	err := run(flags)
	if err != nil {
		log.Fatalf("%v", err)
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
	fmt.Println("  --version                  Show version and exit")
	fmt.Println("")
	fmt.Printf("Version: %v\n", version)
	fmt.Println("")
}

// Run DefaultCmd - Default command for Kong CLI framework.
func run(global *cliGlobal) error {
	slackMessageAttachments := []slack.Attachment{}

	// break down subjects
	subjects := strings.Split(*global.subjects, ",")

	for _, subject := range subjects {
		client := &http.Client{}
		subjectLink := fmt.Sprintf("https://%v", subject)

		resp, err := client.Head(subjectLink)
		if err != nil {
			log.Printf("%v", err)
			continue
		}
		defer resp.Body.Close()

		certs := resp.TLS.PeerCertificates

		for _, cert := range certs {
			pastDue := false
			certDates := &certificateDates{}
			renewBefore, err := strconv.Atoi(*global.renewBefore)
			if err != nil {
				return err
			}

			if subject == cert.Subject.CommonName {
				pastDue, certDates = isAfterRenewDate(cert, renewBefore)
			} else if contains(cert.DNSNames, subject) {
				pastDue, certDates = isAfterRenewDate(cert, renewBefore)
			} else {
				// probably chain cert.
				continue
			}

			if pastDue {
				log.Printf("%v - expires on: %v - renew before %v [ PastDue ]", subject, cert.NotAfter, certDates.renewBeforeDate)
				attachment := slack.Attachment{
					Title:     subject,
					TitleLink: subjectLink,
					Pretext:   fmt.Sprintf(":warning: TLS cert for %v will expire in less than %v days.", subject, renewBefore),
					Color:     "danger",
					Fields: []slack.AttachmentField{
						slack.AttachmentField{
							Title: "Certificate Expires",
							Value: certDates.expirationDate.UTC().Format("Mon Jan 2 15:04:05 MST 2006"),
						},
						slack.AttachmentField{
							Title: "Certificate Renew By",
							Value: certDates.renewBeforeDate.UTC().Format("Mon Jan 2 15:04:05 MST 2006"),
						},
						slack.AttachmentField{
							Title: "Certificate Issued By",
							Value: cert.Issuer.CommonName,
						},
						slack.AttachmentField{
							Title: "Subject Common Name",
							Value: cert.Subject.CommonName,
						},
						slack.AttachmentField{
							Title: "Subject Alternative Names",
							Value: strings.Join(cert.DNSNames, "\n"),
						},
					},
				}
				slackMessageAttachments = append(slackMessageAttachments, attachment)
			} else {
				log.Printf("%v - expires on: %v - renew before %v [ OK ]", subject, cert.NotAfter, certDates.renewBeforeDate)
			}
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
//                    true if after renew date (bad)
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
			ExcludeArchived: "true",
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
				log.Printf("Message successfully sent to channel %s at %s", channelID, timestamp)
			}
		}
	}
	return nil
}
