package cli

const (
	AppName        = "sandboxec"
	AppDescription = "A lightweight command sandbox for Linux, built on Landlock."
	AppAuthor      = "Dwi Siswanto <me@dw1.io>"

	AppUsage = `Usage:
  sandboxec [OPTIONS] [COMMAND [ARG...]]
`
	AppRights = `Rights:
  fs:
    read|r, read_exec|rx, write|w, read_write|rw, read_write_exec|rwx
  net:
    bind|b, connect|c, bind_connect|bc
`
	AppExamples = `Examples:
  sandboxec --fs rx:/usr echo hello
  sandboxec --fs rx:/usr -- ls /usr
  sandboxec --fs rx:/usr --net c:<PORT> -- curl http://127.0.0.1:<PORT>
  sandboxec --mode mcp --fs rx:/usr --fs rw:$PWD --net c:443
`
)

var (
	AppVersion     = "v0.2.2"
	AppBuildCommit = ""
	AppBuildDate   = ""
)
