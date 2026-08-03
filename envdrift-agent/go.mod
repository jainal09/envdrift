module github.com/jainal09/envdrift-agent

// The MANDATORY minimum (Renovate-tracked, depType golang). This carries the
// GO-2026-4602 stdlib security floor (os fixed in go1.25.8): a `toolchain`
// directive is only a suggestion that GOTOOLCHAIN=local ignores, so the go
// directive itself must exclude compilers that ship the vulnerable os
// package into the released agent binaries.
go 1.25.12

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
	golang.org/x/sys v0.47.0 // indirect
)
