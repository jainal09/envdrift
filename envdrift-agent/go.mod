module github.com/jainal09/envdrift-agent

// The MANDATORY minimum (Renovate-tracked, depType golang). This carries the
// stdlib security floor (reachable: GO-2026-4602 os fixed in go1.26.1,
// GO-2026-4971 net in go1.26.3; go1.26.6 clears every known stdlib advisory,
// reachable or not; golang.org/x/sys >= v0.48.0 needs go1.26): a `toolchain`
// directive is only a suggestion that GOTOOLCHAIN=local ignores, so the go
// directive itself must exclude compilers that ship vulnerable stdlib
// packages into the released agent binaries.
go 1.26.6

require (
	github.com/fsnotify/fsnotify v1.10.1
	github.com/gen2brain/beeep v0.11.2
	github.com/pelletier/go-toml/v2 v2.4.3
	github.com/spf13/cobra v1.10.2
)

require (
	git.sr.ht/~jackmordaunt/go-toast v1.1.2 // indirect
	github.com/esiqveland/notify v0.14.0 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/godbus/dbus/v5 v5.2.2 // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/jackmordaunt/icns/v3 v3.0.1 // indirect
	github.com/nfnt/resize v0.0.0-20180221191011-83c6a9932646 // indirect
	github.com/sergeymakinen/go-bmp v1.0.0 // indirect
	github.com/sergeymakinen/go-ico v1.0.0 // indirect
	github.com/spf13/pflag v1.0.10 // indirect
	github.com/tadvi/systray v0.0.0-20190226123456-11a2b8fa57af // indirect
	golang.org/x/sys v0.48.0 // indirect
)
