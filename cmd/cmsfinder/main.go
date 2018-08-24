package main

import (
	"flag"
	"fmt"

	"github.com/chennqqi/go-cmsfinder"
)

func main() {
	var dir string
	var rule string
	flag.StringVar(&dir, "d", "", "set dir name")
	flag.StringVar(&rule, "r", "signatures.json", "set rule name, default signatures.json")

	flag.Parse()

	cms, err := cmsfinder.Load(rule)
	if err != nil {
		fmt.Println("Load Rule ERROR:", err)
		return
	}
	apps, err := cms.Scan(dir)
	if err != nil {
		fmt.Println("Load Rule ERROR:", err)
		return
	} else {
		fmt.Println("RESULT:")
		fmt.Println(apps)
	}
}
