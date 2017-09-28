VERSION=$(shell git describe --tags --abbrev=0 --dirty="-dev")

all: clean releasetool

releasetool:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "-X main.Version=$(VERSION)" -a -installsuffix cgo -o releasetool-linux-amd64 .
clean:
	rm -f releasetool-linux-amd64

release: releasetool
	go get github.com/jckimble/releasetool
	$(GOPATH)/bin/releasetool release --user jckimble --repo releasetool --tag $(VERSION) --name "Automatic Release $(VERSION)" --description "" releasetool-linux-amd64
