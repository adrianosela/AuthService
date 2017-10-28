package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/adrianosela/AuthService/library/jwtvalidation"
	cli "gopkg.in/urfave/cli.v1"
)

func main() {

	app := cli.NewApp()
	app.EnableBashCompletion = true
	app.Usage = "JWT Validation CLI"
	app.CommandNotFound = func(c *cli.Context, command string) {
		fmt.Println("[ERROR] The command provided is not supported: ", command)
		c.App.Run([]string{"help"})
	}

	app.Commands = []cli.Command{
		cli.Command{
			Name:   "validate",
			Usage:  "Validate a given JWT",
			Action: validate,
			Flags: []cli.Flag{
				cli.StringFlag{
					Name:  "jwt",
					Usage: "The JWT itself",
				},
				cli.StringFlag{
					Name:  "iss",
					Usage: "The domain of the JWT issuer",
				},
				cli.StringFlag{
					Name:  "aud",
					Usage: "The JWT's target audience",
				},
				cli.StringFlag{
					Name:  "grps",
					Usage: "Comma separated groups",
				},
			},
		},
	}

	if err := app.Run(os.Args); err != nil {
		log.Fatal(err)
	}
}

func validate(ctx *cli.Context) error {
	groupString := ctx.String("grps")
	tkString := ctx.String("jwt")
	if tkString == "" {
		return errors.New("jwt is a required flag")
	}
	iss := ctx.String("iss")
	if iss == "" {
		return errors.New("iss is a required flag")
	}
	aud := ctx.String("aud")

	grps := strings.Split(groupString, ",")
	if groupString == "" { //split function returns 1 empty string if an empty string is split
		grps = []string{}
	}

	cc, err := jwtvalidation.ValidateToken(tkString, iss, aud, grps)
	if err != nil {
		return fmt.Errorf("[ERROR] Could not validate JWT: %s", err)
	}

	jsonbytes, err := json.Marshal(cc)
	if err != nil {
		return fmt.Errorf("[ERROR] Could not marshall custom claims: %s", err)
	}

	fmt.Println(string(jsonbytes))
	return nil
}
