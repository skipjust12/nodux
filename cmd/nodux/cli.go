package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/skipjust12/nodux/internal/detector"
	"github.com/skipjust12/nodux/internal/server"
	"github.com/skipjust12/nodux/internal/silence"
)

// commands talk to a running nodux over its control socket.
var commands = map[string]func(args []string) int{
	"status":    cmdStatus,
	"silence":   cmdSilence,
	"silences":  cmdSilences,
	"unsilence": cmdUnsilence,
}

func usage() {
	fmt.Fprint(os.Stderr, `Usage:
  nodux [--config config.yaml]        run the daemon
  nodux --version

Commands for a running nodux (over its control socket):
  nodux status [--json]               open problems, silences, receivers
  nodux silence <match> <duration> [-c comment]
                                      mute alerts, e.g.
                                        nodux silence api 30m
                                        nodux silence detector=memory,container=api 2h
                                        nodux silence project=shop 1d -c "migration"
                                        nodux silence all 15m
  nodux silences [--json]             list active silences
  nodux unsilence <id>                end a silence early

  --socket PATH                       control socket (default $NODUX_SOCKET or `+server.DefaultSocket+`)
`)
}

// cliArgs is a tiny flag parser that, unlike package flag, accepts flags
// after positional arguments (nodux silence api 30m -c "deploy").
type cliArgs struct {
	socket     string
	json       bool
	comment    string
	positional []string
}

func parseCLI(args []string) (cliArgs, error) {
	a := cliArgs{socket: os.Getenv("NODUX_SOCKET")}
	if a.socket == "" {
		a.socket = server.DefaultSocket
	}
	for i := 0; i < len(args); i++ {
		arg := args[i]
		name, value, hasValue := strings.Cut(strings.TrimLeft(arg, "-"), "=")
		if !strings.HasPrefix(arg, "-") || arg == "-" {
			a.positional = append(a.positional, arg)
			continue
		}
		takeValue := func() (string, error) {
			if hasValue {
				return value, nil
			}
			if i+1 >= len(args) {
				return "", fmt.Errorf("%s needs a value", arg)
			}
			i++
			return args[i], nil
		}
		var err error
		switch name {
		case "socket":
			a.socket, err = takeValue()
		case "c", "comment":
			a.comment, err = takeValue()
		case "json":
			a.json = true
		case "h", "help":
			return a, errHelp
		default:
			return a, fmt.Errorf("unknown flag %s", arg)
		}
		if err != nil {
			return a, err
		}
	}
	return a, nil
}

var errHelp = fmt.Errorf("help")

// run parses args, checks the number of positional arguments and runs
// fn with a client.
func run(args []string, nargs int, fn func(context.Context, *server.Client, cliArgs) error) int {
	a, err := parseCLI(args)
	if err == nil && len(a.positional) != nargs {
		err = fmt.Errorf("expected %d argument(s), got %d", nargs, len(a.positional))
	}
	if err != nil {
		usage()
		if err == errHelp {
			return 0
		}
		fmt.Fprintln(os.Stderr, "\nerror:", err)
		return 2
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := fn(ctx, server.NewClient(a.socket), a); err != nil {
		fmt.Fprintln(os.Stderr, "nodux:", err)
		return 1
	}
	return 0
}

func cmdStatus(args []string) int {
	return run(args, 0, func(ctx context.Context, c *server.Client, a cliArgs) error {
		st, err := c.Status(ctx)
		if err != nil {
			return err
		}
		if a.json {
			return printJSON(st)
		}
		printStatus(os.Stdout, st, time.Now())
		return nil
	})
}

func cmdSilence(args []string) int {
	return run(args, 2, func(ctx context.Context, c *server.Client, a cliArgs) error {
		s, err := c.AddSilence(ctx, server.SilenceRequest{Matcher: a.positional[0], Duration: a.positional[1], Comment: a.comment})
		if err != nil {
			return err
		}
		fmt.Printf("silenced %s until %s (id %s)\n", s.Matcher, s.Until.Local().Format("2006-01-02 15:04"), s.ID)
		return nil
	})
}

func cmdSilences(args []string) int {
	return run(args, 0, func(ctx context.Context, c *server.Client, a cliArgs) error {
		list, err := c.Silences(ctx)
		if err != nil {
			return err
		}
		if a.json {
			return printJSON(list)
		}
		if len(list) == 0 {
			fmt.Println("No active silences.")
			return nil
		}
		printSilences(os.Stdout, list, time.Now())
		return nil
	})
}

func cmdUnsilence(args []string) int {
	return run(args, 1, func(ctx context.Context, c *server.Client, a cliArgs) error {
		if err := c.RemoveSilence(ctx, a.positional[0]); err != nil {
			return err
		}
		fmt.Println("removed silence", a.positional[0])
		return nil
	})
}

func printJSON(v any) error {
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func printStatus(w io.Writer, st *server.Status, now time.Time) {
	docker := "up"
	if !st.DockerUp {
		docker = "UNREACHABLE"
	}
	fmt.Fprintf(w, "nodux %s on %s, up %s; docker %s", st.Version, st.Host, since(now, st.Started), docker)
	if st.LastPoll != nil {
		fmt.Fprintf(w, ", last poll %s ago", since(now, *st.LastPoll))
	}
	fmt.Fprintln(w)

	fmt.Fprintln(w)
	if len(st.Episodes) == 0 {
		fmt.Fprintln(w, "No open problems.")
	} else {
		fmt.Fprintln(w, "OPEN PROBLEMS")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  SEVERITY\tDETECTOR\tSUBJECT\tFOR\tMESSAGE")
		for _, ep := range st.Episodes {
			subject := ep.Container
			if subject == "" {
				subject = ep.Resource
			}
			msg := detector.Truncate(strings.Join(strings.Fields(ep.Message), " "), 100)
			if ep.Silenced {
				msg += " [silenced]"
			}
			fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\t%s\n", ep.Severity, ep.Detector, subject, since(now, ep.Since), msg)
		}
		tw.Flush()
	}

	if len(st.Silences) > 0 {
		fmt.Fprintln(w, "\nSILENCES")
		printSilences(w, st.Silences, now)
	}
	if len(st.DeployWindows) > 0 {
		fmt.Fprintln(w, "\nDEPLOY WINDOWS")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		for _, win := range st.DeployWindows {
			fmt.Fprintf(tw, "  %s\t%s\tends in %s\n", win.Scope, win.Name, since(win.Until, now))
		}
		tw.Flush()
	}

	if len(st.Receivers) > 0 {
		fmt.Fprintln(w, "\nRECEIVERS")
		tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
		fmt.Fprintln(tw, "  NAME\tSENT\tFAILED\tDROPPED\tQUEUED")
		for _, r := range st.Receivers {
			fmt.Fprintf(tw, "  %s\t%d\t%d\t%d\t%d\n", r.Name, r.Sent, r.Failed, r.Dropped, r.Pending)
		}
		tw.Flush()
	}

	if u := st.LLM; u != nil {
		fmt.Fprint(w, "\nLLM: ")
		if u.MaxPerHour > 0 {
			fmt.Fprintf(w, "%d of %d calls left this hour; ", u.Remaining, u.MaxPerHour)
		}
		fmt.Fprintf(w, "%d ok, %d failed, %d skipped over budget\n", u.OK, u.Failed, u.OverBudget)
	}
}

func printSilences(w io.Writer, list []silence.Silence, now time.Time) {
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "  ID\tMATCH\tENDS IN\tCOMMENT")
	for _, s := range list {
		fmt.Fprintf(tw, "  %s\t%s\t%s\t%s\n", s.ID, s.Matcher, since(s.Until, now), s.Comment)
	}
	tw.Flush()
}

// since renders now - t like "45s", "12m", "3h5m", "2d4h".
func since(now, t time.Time) string {
	d := now.Sub(t)
	if d < 0 {
		d = 0
	}
	switch {
	case d < time.Minute:
		return fmt.Sprintf("%ds", int(d.Seconds()))
	case d < time.Hour:
		return fmt.Sprintf("%dm", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh%dm", int(d.Hours()), int(d.Minutes())%60)
	default:
		return fmt.Sprintf("%dd%dh", int(d.Hours())/24, int(d.Hours())%24)
	}
}
