BINARY   := subnet_finder
CMD      := subnet_scaner
APPNAME  := Subnet Scanner
BUILDDIR := bin
PREFIX   ?= $(HOME)/.local
BINDIR   := $(PREFIX)/bin
APPDIR   := $(HOME)/Applications/$(APPNAME).app

.PHONY: all build icon app install uninstall clean

all: build

build:
	mkdir -p $(BUILDDIR)
	CGO_ENABLED=1 go build -o $(BUILDDIR)/$(BINARY) .

icon:
	go run ./scripts/genicon build/icon.png
	mkdir -p build/AppIcon.iconset
	sips -z 16 16     build/icon.png --out build/AppIcon.iconset/icon_16x16.png >/dev/null
	sips -z 32 32     build/icon.png --out build/AppIcon.iconset/icon_16x16@2x.png >/dev/null
	sips -z 32 32     build/icon.png --out build/AppIcon.iconset/icon_32x32.png >/dev/null
	sips -z 64 64     build/icon.png --out build/AppIcon.iconset/icon_32x32@2x.png >/dev/null
	sips -z 128 128   build/icon.png --out build/AppIcon.iconset/icon_128x128.png >/dev/null
	sips -z 256 256   build/icon.png --out build/AppIcon.iconset/icon_128x128@2x.png >/dev/null
	sips -z 256 256   build/icon.png --out build/AppIcon.iconset/icon_256x256.png >/dev/null
	sips -z 512 512   build/icon.png --out build/AppIcon.iconset/icon_256x256@2x.png >/dev/null
	sips -z 512 512   build/icon.png --out build/AppIcon.iconset/icon_512x512.png >/dev/null
	sips -z 1024 1024 build/icon.png --out build/AppIcon.iconset/icon_512x512@2x.png >/dev/null
	iconutil -c icns -o build/AppIcon.icns build/AppIcon.iconset

app: build icon
	rm -rf "$(APPDIR)"
	mkdir -p "$(APPDIR)/Contents/MacOS" "$(APPDIR)/Contents/Resources"
	cp $(BUILDDIR)/$(BINARY) "$(APPDIR)/Contents/MacOS/$(CMD)"
	cp packaging/macos/Info.plist "$(APPDIR)/Contents/Info.plist"
	cp build/AppIcon.icns "$(APPDIR)/Contents/Resources/AppIcon.icns"
	/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f "$(APPDIR)"

install: app
	mkdir -p $(BINDIR)
	rm -f $(BINDIR)/$(CMD)
	printf '%s\n' '#!/bin/sh' 'exec open -a "$(APPDIR)" "$$@"' > $(BINDIR)/$(CMD)
	chmod +x $(BINDIR)/$(CMD)

uninstall:
	rm -f $(BINDIR)/$(CMD)
	rm -rf "$(APPDIR)"

clean:
	rm -rf $(BUILDDIR) build
