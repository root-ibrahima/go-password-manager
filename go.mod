module go-password-manager

go 1.25.0

toolchain go1.25.4

require (
	github.com/gorilla/mux v1.8.1
	github.com/joho/godotenv v1.5.1
	github.com/manifoldco/promptui v0.9.0
	github.com/mutecomm/go-sqlcipher/v4 v4.4.2
	github.com/spf13/cobra v1.10.2
	golang.org/x/crypto v0.36.0
	golang.org/x/term v0.30.0
)

require (
	github.com/chzyer/readline v0.0.0-20180603132655-2972be24d48e // indirect
	github.com/inconshreveable/mousetrap v1.1.0 // indirect
	github.com/spf13/pflag v1.0.9 // indirect
	golang.org/x/sys v0.31.0 // indirect
)

replace go-password-manager => ./
