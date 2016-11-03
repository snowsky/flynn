package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/url"

	"github.com/flynn/flynn/controller/client"
	ct "github.com/flynn/flynn/controller/types"
	"github.com/flynn/go-docopt"
)

func init() {
	register("log-sink", runLogSink, `
usage: flynn log-sink
       flynn log-sink add syslog <url> [<prefix>]
       flynn log-sink remove <id>

Manage cluster log sinks.

Commands:
       With no arguments, shows a list of log sinks.

       add     adds a new log sink to the cluster.
       remove  removes an existing log sink from the cluster.
`)
}

func runLogSink(args *docopt.Args, client controller.Client) error {
	if args.Bool["add"] {
		switch {
		case args.Bool["syslog"]:
			return runLogSinkAddSyslog(args, client)
		default:
			return fmt.Errorf("Sink kind not supported")
		}
	}
	if args.Bool["remove"] {
		return runLogSinkRemove(args, client)
	}

	sinks, err := client.ListSinks()
	if err != nil {
		return err
	}

	w := tabWriter()
	defer w.Flush()

	listRec(w, "ID", "KIND", "CONFIG")
	for _, j := range sinks {
		listRec(w, j.ID, j.Kind, string(j.Config))
	}

	return err
}

func runLogSinkAddSyslog(args *docopt.Args, client controller.Client) error {
	u, err := url.Parse(args.String["<url>"])
	if err != nil {
		return fmt.Errorf("Invalid syslog URL: %s", err)
	}
	switch u.Scheme {
	case "tcp", "tls":
	default:
		return fmt.Errorf("Invalid syslog protocol: %s", u.Scheme)
	}
	// TODO(jpg) can we reasonably validate template?
	config, _ := json.Marshal(ct.SyslogSinkConfig{
		Prefix: args.String["<prefix>"],
		URL:    u.String(),
	})
	sink := &ct.Sink{
		Kind:   ct.SinkKindSyslog,
		Config: config,
	}
	if err := client.CreateSink(sink); err != nil {
		return err
	}

	log.Printf("Created sink %s.", sink.ID)

	return nil
}

func runLogSinkRemove(args *docopt.Args, client controller.Client) error {
	id := args.String["<id>"]

	res, err := client.DeleteSink(id)
	if err != nil {
		return err
	}

	log.Printf("Deleted sink %s.", res.ID)

	return nil
}
