package main

import (
	"fmt"

	"example.com/upstream"
)

func main() { fmt.Println("OUT:", upstream.Greeting()) }
