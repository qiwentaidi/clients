package main

import (
	"fmt"

	"github.com/qiwentaidi/clients"
)

func main() {
	client := clients.NewRestyClient(nil, false)
	resp, err := clients.SimpleGet("https://www.baidu.com/2009", client)
	if err != nil {
		panic(err)
	}
	fmt.Println("Status:", resp.Status())
	fmt.Println("Title:", clients.GetTitle(resp.Body()))
}
