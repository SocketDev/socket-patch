package main

import (
	"fmt"

	"github.com/pmezard/go-difflib/difflib"
)

func main() { fmt.Println("OUT: SEED", len(difflib.SplitLines("one\ntwo\n"))) }
