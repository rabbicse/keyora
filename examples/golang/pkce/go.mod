module example.com/keyora-pkce

go 1.24

require github.com/rabbicse/keyora v0.0.0

// Inside this repository the example builds against the local source. In your
// own project, delete this line and run: go get github.com/rabbicse/keyora@latest
replace github.com/rabbicse/keyora => ../../..
