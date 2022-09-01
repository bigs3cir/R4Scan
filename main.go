package main

import (
	"bytes"
	"context"
	"fmt"
	"github.com/PuerkitoBio/goquery"
	"github.com/alexflint/go-arg"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"io"
	"log"
	"os"
	"r4scan/core"
	proto2 "r4scan/core/local"
	"r4scan/http"
	"r4scan/validator"
	"runtime"
	"strings"
)

func init() {

	runtime.GOMAXPROCS(runtime.NumCPU())
}

func main() {

	arg.MustParse(&args)
	if args.Version {
		fmt.Println(version())
		os.Exit(0)
	}

	startUp()
}

func startUp() {

	if err := validator.Validator(&args); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	//aaa := make(chan map[string]string)

	_, addr, err := core.RunAsLocal()
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	fmt.Println(addr)

	conn, err := grpc.Dial(addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	client := proto2.NewR4ScanClient(conn)

	r, err := client.Create(context.Background(), &proto2.CreateRequest{Test: "aaaa"})
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}

	for {
		res, err := r.Recv()
		if err == io.EOF {
			break
		}
		if err != nil {
			log.Fatalf("ListStr get stream err: %v", err)
		}
		fmt.Println(res.String())
	}

	fmt.Println(111)

	//fmt.Println(r.String())
	//
	//r, err = client.Create(context.Background(), &proto2.CreateRequest{Test: "aaaa"})
	//if err != nil {
	//	fmt.Println(err)
	//	os.Exit(1)
	//}
	//
	//fmt.Println(r.String())

	//	var datas = `
	//<html>
	//<body>
	//	<table>
	//    <tr>
	//      <td>
	//          <!-- comment #1 -->
	//          Name
	//      </td>
	//      <td>
	//        <span style="text-decoration:line-through">
	//            <!-- comment #2 -->
	//            Name
	//        </span>
	//      </td>
	//			<td>
	//				<div>
	//					<p>
	//						Some content
	//						<!-- comment #3 -->
	//					</p>
	//				</div>
	//			</td>
	//    </tr>
	//	</table>
	//</body>
	//</html>
	//`

	proxys, err := http.NewProxy("vless://4ce4eec8-6319-4af3-bcad-91658a176445@127.0.0.1:9999?encryption=none&security=tls&sni=9.com&type=tcp&headerType=none#a\n")
	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	hclient := http.NewClient().SetCertificateVerify(true).SetProxy(proxys)
	resp, err := hclient.Do(args.URL[0])

	defer http.ReleaseResponse(resp)

	if err != nil {
		log.Fatal(err)
		os.Exit(1)
	}

	fmt.Println(string(resp.Body()))

	os.Exit(1)

	//res, _ := http.Get("https://github.com/PuerkitoBio/goquery")

	doc, err := goquery.NewDocumentFromReader(bytes.NewReader(resp.Body()))

	if err != nil {
		log.Fatal(err)
	}

	//fmt.Println(doc.Next().Length())

	//fmt.Println(doc.Children().Length())
	ii := 0
	doc.Find("*").Contents().Each(func(i int, selection *goquery.Selection) {
		ii++
		//fmt.Println(goquery.NodeName(selection))
		for _, a := range selection.Get(0).Attr {
			if strings.Contains(a.Key, "action") {
				fmt.Printf(`%s="%s"`+"\n", a.Key, a.Val)
			}

		}

		if selection.Contents().Length() == 0 {
			//for _, a := range selection.Get(0).Attr {
			//	fmt.Printf(`%s="%s"`+"\n", a.Key, a.Val)
			//}
			//fmt.Println(goquery.NodeName(selection))
			//fmt.Println("haha:" + strings.TrimSpace(selection.Text()))
			//fmt.Println("")
		}

	})

	fmt.Println(ii)

	doc.Each(func(i int, selection *goquery.Selection) {
		//fmt.Println(selection.Html())
	})

	doc.Each(func(i int, selection *goquery.Selection) {
		//fmt.Println(selection.NextAll().Length())
	})

	//x, _ := doc.Html()
	//
	//fmt.Println(x)

	//for {
	//}

	fmt.Println(1)

}
