package main

import (
	"fmt"

	"example.com/local"
	"example.com/upstream"
)

func main() { fmt.Println("OUT:", upstream.Greeting(), local.Name()) }
