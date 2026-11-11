// Package cli implements rpwd subcommands.
package cli

var commands = []command{
	{name: "init", summary: "create a new vault", run: cmdInit},
	{name: "ls", summary: "list entries", run: cmdLs},
	{name: "show", summary: "<id> [--print]  show entry, copy password (--print: to stdout)", run: cmdShow},
	{name: "add", summary: "add an entry (interactive)", run: cmdAdd},
	{name: "edit", summary: "<id>  edit an entry, Enter keeps a value", run: cmdEdit},
	{name: "rm", summary: "<id>  delete an entry", run: cmdRm},
	{name: "passwd", summary: "change master password", run: cmdPasswd},
	{name: "dump", summary: "<dir> [--decrypt]  dump vault to dir (--decrypt: plain CSV)", run: cmdDump},
	{name: "lock", summary: "lock vault for agent", run: cmdLock},
	{name: "status", summary: "get agent status", run: cmdStatus},
	{name: "__agent", hidden: true, summary: "agent workflow", run: cmdAgent},
}

type command struct {
	name    string
	summary string
	run     func(a *app, args []string) error
	hidden  bool
}
