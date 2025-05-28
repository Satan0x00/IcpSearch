package main

import (
	"bufio"
	"bytes"
	"crypto/md5"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/gookit/color"
	"github.com/tidwall/gjson"
	"github.com/xuri/excelize/v2"
	"golang.org/x/net/proxy"
)

type QueryRequest struct {
	UnitName    string `json:"unitName"`
	PageNum     int    `json:"pageNum"`
	PageSize    int    `json:"pageSize"`
	ServiceType string `json:"serviceType"`
}

type QueryResponse struct {
	Code   int    `json:"code"`
	Msg    string `json:"msg"`
	Params struct {
		List []struct {
			Domain      string `json:"domain"`
			ServiceName string `json:"serviceName"`
			UnitName    string `json:"unitName"`
		} `json:"list"`
	} `json:"params"`
}

type AuthResp struct {
	Code   int    `json:"code"`
	Msg    string `json:"msg"`
	Params struct {
		Token string `json:"bussiness"`
		Sign  string `json:"sign"`
	} `json:"params"`
}

var cachedToken string
var cachedSign string
var tokenExpireAt int64
var httpClient *http.Client

func getTokenAndSignIfNeeded() (string, string, error) {
	now := time.Now().Unix()
	if cachedToken != "" && tokenExpireAt > now+10 {
		return cachedToken, cachedSign, nil
	}
	urlStr := "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/auth"
	timeStamp := strconv.FormatInt(time.Now().UnixNano()/1e6, 10) // 毫秒
	authKey := fmt.Sprintf("%x", md5.Sum([]byte("testtest"+timeStamp)))
	data := url.Values{}
	data.Set("authKey", authKey)
	data.Set("timeStamp", timeStamp)

	req, err := http.NewRequest("POST", urlStr, strings.NewReader(data.Encode()))
	if err != nil {
		return "", "", err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded; charset=UTF-8")
	req.Header.Set("Referer", "https://beian.miit.gov.cn/")
	req.Header.Set("User-Agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64)")

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, _ := ioutil.ReadAll(resp.Body)

	if len(body) > 0 && body[0] == '<' {
		preview := string(body)
		if len(preview) > 100 {
			preview = preview[:100] + "..."
		}
		return "", "", fmt.Errorf("返回HTML页面，需要更换Ip: %s", preview)
	}

	var auth AuthResp
	err = json.Unmarshal(body, &auth)
	if err != nil {
		return "", "", fmt.Errorf("JSON解析失败: %v, 响应内容: %s", err, string(body))
	}
	if auth.Code != 200 {
		return "", "", fmt.Errorf("auth failed: %s", auth.Msg)
	}
	// 解析expire字段，设置token过期时间
	expire := gjson.Get(string(body), "params.expire").Int()
	if expire == 0 {
		expire = 60 // 默认60秒
	}
	tokenExpireAt = time.Now().Unix() + expire/1000
	cachedToken = auth.Params.Token
	cachedSign = auth.Params.Sign
	return cachedToken, cachedSign, nil
}

// 解析目标，支持括号拆分
func parseTargets(targetArg string) ([]string, error) {
	var targets []string
	if _, err := os.Stat(targetArg); err == nil {
		// 文件
		f, err := os.Open(targetArg)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		scanner := bufio.NewScanner(f)
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line == "" {
				continue
			}
			ts := splitBrackets(line)
			targets = append(targets, ts...)
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	} else {
		// 单个目标
		ts := splitBrackets(targetArg)
		targets = append(targets, ts...)
	}
	uniq := map[string]struct{}{}
	var result []string
	for _, t := range targets {
		t = strings.TrimSpace(t)
		if t == "" {
			continue
		}
		if _, ok := uniq[t]; !ok {
			uniq[t] = struct{}{}
			result = append(result, t)
		}
	}
	return result, nil
}

// 拆分括号内容
func splitBrackets(s string) []string {
	re := regexp.MustCompile(`^(.*?)\((.*?)\)$`)
	if m := re.FindStringSubmatch(s); len(m) == 3 {
		return []string{strings.TrimSpace(m[1]), strings.TrimSpace(m[2])}
	}
	return []string{s}
}

// 类型映射
var typeMap = map[string]string{
	"1": "1", // 网站
	"2": "6", // APP
	"3": "7", // 小程序
}
var typeName = map[string]string{
	"1": "网站",
	"2": "APP",
	"3": "小程序",
}

// 代理设置
func setProxy(proxyStr string) error {
	if proxyStr == "" {
		httpClient = &http.Client{Timeout: 20 * time.Second}
		return nil
	}
	u, err := url.Parse(proxyStr)
	if err != nil {
		return err
	}
	var transport http.RoundTripper
	switch u.Scheme {
	case "http", "https":
		transport = &http.Transport{
			Proxy: http.ProxyURL(u),
		}
	case "socks5":
		dialer, err := proxy.SOCKS5("tcp", u.Host, nil, proxy.Direct)
		if err != nil {
			return err
		}
		transport = &http.Transport{
			Dial: dialer.Dial,
		}
	default:
		return errors.New("不支持的代理协议")
	}
	httpClient = &http.Client{Transport: transport, Timeout: 20 * time.Second}
	return nil
}

// 查询单个目标单类型
func queryIcp(unitName, serviceType string) ([]string, error) {
	var try int
	for try = 0; try < 2; try++ {
		token, sign, err := getTokenAndSignIfNeeded()
		if err != nil {
			return nil, err
		}
		query := QueryRequest{
			UnitName:    unitName,
			PageNum:     1,
			PageSize:    10,
			ServiceType: serviceType,
		}
		b, _ := json.Marshal(query)
		url := "https://hlwicpfwc.miit.gov.cn/icpproject_query/api/icpAbbreviateInfo/queryByCondition/"
		req, err := http.NewRequest("POST", url, bytes.NewReader(b))
		if err != nil {
			return nil, err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("Referer", "https://beian.miit.gov.cn/")
		req.Header.Set("Token", token)
		req.Header.Set("Sign", sign)
		resp, err := httpClient.Do(req)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		body, _ := io.ReadAll(resp.Body)
		var qr QueryResponse
		err = json.Unmarshal(body, &qr)
		if err != nil {
			return nil, err
		}
		if qr.Code == 401 || (qr.Code != 200 && strings.Contains(qr.Msg, "token")) {
			cachedToken = ""
			cachedSign = ""
			continue
		}
		if qr.Code != 200 {
			return nil, fmt.Errorf(qr.Msg)
		}
		if len(qr.Params.List) == 0 {
			return nil, nil
		}
		var result []string
		for _, item := range qr.Params.List {
			if serviceType == "1" {
				result = append(result, item.Domain)
			} else {
				result = append(result, item.ServiceName)
			}
		}
		return result, nil
	}
	return nil, fmt.Errorf("多次尝试后仍然失败")
}

// 查询单个目标单类型，失败自动重试最多5次
func queryIcpWithRetry(unitName, serviceType string) ([]string, error) {
	var lastErr error
	for i := 0; i < 5; i++ {
		// fmt.Printf("开始查询 [%s][%s]\n", unitName, typeName[serviceType])
		res, err := queryIcp(unitName, serviceType)
		if err == nil {
			// fmt.Printf("成功 [%s][%s]: %v\n", unitName, typeName[serviceType], res)
			return res, nil
		}
		// fmt.Printf("重试第%d次 [%s][%s] 失败: %v\n", i+1, unitName, typeName[serviceType], err)
		lastErr = err
		time.Sleep(2 * time.Second)
	}
	return nil, fmt.Errorf("重试5次后仍然失败: %v", lastErr)
}

func printBanner() {
	cat := `
 /\_/\  
( o.o )  ICP批量备案查询
 > ^ <   by satan github:https://github.com/Satan0x00
`
	color.Style{color.FgMagenta, color.OpBold}.Println(cat)
}

func main() {
	printBanner()
	var targetArg string
	var typeArg string
	var output string
	var proxyStr string

	flag.StringVar(&targetArg, "t", "", "目标单位名或文件")
	flag.StringVar(&typeArg, "type", "1", "类型: 1=网站,2=APP,3=小程序,可组合如1,2,3")
	flag.StringVar(&output, "o", "result.xlsx", "输出Excel文件名")
	flag.StringVar(&proxyStr, "p", "", "代理地址,支持http/https/socks5")

	if len(os.Args) == 1 {
		flag.Usage()
		os.Exit(0)
	}
	flag.Parse()

	if targetArg == "" {
		fmt.Println("请指定目标: -t <单位名或文件>")
		os.Exit(1)
	}

	if err := setProxy(proxyStr); err != nil {
		fmt.Println("代理设置失败:", err)
		os.Exit(1)
	}

	targets, err := parseTargets(targetArg)
	if err != nil {
		fmt.Println("目标解析失败:", err)
		os.Exit(1)
	}
	if len(targets) == 0 {
		fmt.Println("无有效目标")
		os.Exit(1)
	}

	types := strings.Split(typeArg, ",")
	var validTypes []string
	for _, t := range types {
		t = strings.TrimSpace(t)
		if _, ok := typeMap[t]; ok {
			validTypes = append(validTypes, t)
		}
	}
	if len(validTypes) == 0 {
		fmt.Println("无有效类型, 仅支持1,2,3")
		os.Exit(1)
	}

	// 结果表: map[公司名]map[类型]结果
	resultTable := make(map[string]map[string][]string)
	failedCompanies := make(map[string]bool)
	companyCount := len(targets)
	for idx, target := range targets {
		resultTable[target] = make(map[string][]string)
		color.Style{color.FgCyan, color.OpBold}.Printf("\n[%d/%d] 正在查询单位：%s\n", idx+1, companyCount, target)
		for _, t := range validTypes {
			stype := typeMap[t]
			res, err := queryIcpWithRetry(target, stype)
			if err != nil {
				color.Style{color.FgRed, color.OpBold}.Printf("❌ 查询失败 [%s][%s]: %v\n", target, typeName[t], err)
				failedCompanies[target] = true
				continue
			}
			resultTable[target][t] = res
			// 间隔防风控
			time.Sleep(2 * time.Second)
		}
		// 查询后输出公司结果
		if failedCompanies[target] {
			color.Style{color.FgRed, color.OpBold}.Printf("[单位查询失败] %s\n", target)
		} else {
			color.Style{color.FgGreen, color.OpBold}.Printf("[查询结果] %s\n", target)
			for _, t := range validTypes {
				val := strings.Join(resultTable[target][t], ",")
				if val == "" {
					color.Style{color.FgYellow}.Printf("  %s: 无备案\n", typeName[t])
				} else {
					color.Style{color.FgGreen}.Printf("  %s: %s\n", typeName[t], val)
				}
			}
		}
	}

	// 写入Excel
	f := excelize.NewFile()
	sheet := "Sheet1"
	f.SetSheetName("Sheet1", sheet)
	f.SetCellValue(sheet, "A1", "公司名")
	f.SetCellValue(sheet, "B1", "网站")
	f.SetCellValue(sheet, "C1", "APP")
	f.SetCellValue(sheet, "D1", "小程序")
	f.SetCellValue(sheet, "E1", "未备案公司名")
	f.SetCellValue(sheet, "F1", "查询失败公司名")
	row := 2
	// 排序输出
	var keys []string
	for k := range resultTable {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		f.SetCellValue(sheet, fmt.Sprintf("A%d", row), k)
		allEmpty := true
		for i, t := range []string{"1", "2", "3"} {
			col := string('B' + i)
			val := strings.Join(resultTable[k][t], ",")
			f.SetCellValue(sheet, fmt.Sprintf("%s%d", col, row), val)
			if val != "" {
				allEmpty = false
			}
		}
		// 检查是否所有类型都没有备案
		if allEmpty && !failedCompanies[k] {
			f.SetCellValue(sheet, fmt.Sprintf("E%d", row), k)
		}
		// 检查是否查询失败
		if failedCompanies[k] {
			f.SetCellValue(sheet, fmt.Sprintf("F%d", row), k)
		}
		row++
	}
	if err := f.SaveAs(output); err != nil {
		fmt.Println("写入Excel失败:", err)
		os.Exit(1)
	}
	fmt.Printf("查询完成，结果已保存到 %s\n", output)
}
