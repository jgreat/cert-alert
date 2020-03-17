# cert-alert
Simple service to check a list of domains to see if the certs are about to expire. Run as a scheduled job (cron) to check your certs on a regular basis.

Published as a docker container https://hub.docker.com/repository/docker/jgreat/cert-alert

```plain
Usage: cert-alert --subjects=SUBJECTS,...

Connect to websites to see if certs are about to expire.
Send alerts to slack if --slack-token is defined.

Flags:
  --help                     Show this message
  --slack-token=STRING       Token for slack. Will post to all channels @cert-alert is invited to. ($SLACK_TOKEN)
  --renew-before=30          Renew days before cert expiration ($RENEW_BEFORE)
  --subjects=SUBJECTS,...    List of certificate subjects (hostnames) to check. ($SUBJECTS)
  --version                  Show version and exit

Version: 0.0.1
```

## Running in Docker

```plain
docker run -it --rm \
    -e SLACK_TOKEN="xoxb-....." \
    -e SUBJECTS="google.com,my.site.com,example.com" \
    jgreat/cert-alert
```

## Setting up slack

If you want to send alerts to Slack you will need to create an app and add it to your workspace.

https://api.slack.com/apps

Select `Create New App`

* App Name: `cert-alert`
* Development Workspace: `<your workspace>`

### Basic Info

#### Display Information

* App Name: cert-alert
* Short Description: Get alerts when your certificates need to be renewed.
* Pick a color and a Icon.

### OAuth & Permissions

#### Tokens for Your Workspace

* Bot User OAuth Access Token: This is the token you put in `$SLACK_TOKEN`

#### Scopes - Bot Token Scopes

This app needs the following scopes.

* channels:read
* groups:read
* im:read
* mpim:read
* chat:write

### Invite your bot user to a channel

Choose one or more channels you would like alerts to be sent to and invite the `@cert-alert` bot user.

```
/invite @cert-alert
```

### Run the service with `$SLACK_TOKEN`

Add the slack token environment variable when you run the docker container.

## Building Locally

Golang 1.14

```
go clean
go mod tidy
go build -v -ldflags "-X 'main.version=$VERSION'"
```

## Building with Docker

Need to specify ulimit memlock due to bug https://github.com/golang/go/issues/37436

```
docker build --ulimit memlock=-1 --build-arg VERSION=${VERSION} -t jgreat/cert-alert .
```
