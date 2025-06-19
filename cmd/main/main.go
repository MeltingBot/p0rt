package main

import (
	"log"

	"github.com/p0rt/p0rt/cmd"
)

func main() {
	log.SetFlags(log.LstdFlags | log.Lshortfile)
	cmd.Execute()
}