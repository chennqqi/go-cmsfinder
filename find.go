package cmsfinder

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/buger/jsonparser"
	//	cutils "github.com/chennqqi/goutils/c"
	"github.com/edsrzf/mmap-go"
)

var (
	flatVersionExp = regexp.MustCompile(`(?m)^(.*)$`)
	subNextLineExp = regexp.MustCompile(`\r`)
	subSpaceExp    = regexp.MustCompile(`\s+`)
)

type Fingerprints []struct {
	File      string `json:"file"`
	Signature string `json:"signature"`
	Exclude   string `json:"exclude"`
}

type Versions []struct {
	Regex      string `json:"regex"`
	exp        *regexp.Regexp
	Multiline  bool   `json:"multiline, omitempty"`
	File       string `json:"file"`
	Exclude    string `json:"exclude"`
	excludeExp *regexp.Regexp
	FlatFile   bool   `json:"flatfile"`
	Filter     string `json:"filter"`
	filterExp  *regexp.Regexp
}

type Last []string
type Support []string

type App struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type CmsSignature struct {
	Name         string       `json:"name"`
	Fingerprints Fingerprints `json:"fingerprints"`
	Versions     Versions     `json:"versions"`
	Support      Support      `json:"supports"`
	Last         Last         `json:"lasts"`
}

type CmsSignatures []*CmsSignature

func Load(name string) (CmsSignatures, error) {
	txt, err := ioutil.ReadFile(name)
	if err != nil {
		return nil, err
	}
	var rCs CmsSignatures
	err = jsonparser.ObjectEach(txt, func(key, value []byte, t jsonparser.ValueType,
		offset int) error {
		cs := new(CmsSignature)
		cs.Name = string(key)
		err := json.Unmarshal(value, cs)
		if err != nil {
			fmt.Println("ERROR:", string(value), cs)
			return err
		}
		var l Last
		err = jsonparser.ObjectEach(value, func(key, value []byte, t jsonparser.ValueType,
			offset int) error {
			l = append(l, string(value))
			return nil
		}, "last")
		if err == nil {
			cs.Last = l
		}

		var s Support
		err = jsonparser.ObjectEach(value, func(key, value []byte, t jsonparser.ValueType,
			offset int) error {
			s = append(s, string(value))
			return nil
		}, "support")

		if err == nil {
			cs.Support = s
		}
		for i := 0; i < len(cs.Versions); i++ {
			pv := &cs.Versions[i]
			pv.Regex = strings.Replace(pv.Regex, "?P<version>", "", 1)
			pv.Exclude = strings.Replace(pv.Exclude, "?P<version>", "", 1)
			pv.Filter = strings.Replace(pv.Filter, "?P<version>", "", 1)
			if pv.Multiline {
				pv.exp = regexp.MustCompile(`(?m)` + pv.Regex)
			} else if pv.Regex != "" {
				pv.exp = regexp.MustCompile(pv.Regex)
			}
			if pv.Exclude != "" {
				pv.excludeExp = regexp.MustCompile(pv.Exclude)
			}
			if pv.Filter != "" {
				pv.filterExp = regexp.MustCompile(pv.Filter)
			}
		}

		rCs = append(rCs, cs)
		return nil
	})

	return rCs, err
}

func fileContains(name string, signature string) bool {
	return false
}

func (c CmsSignatures) Scan(dir string) ([]App, error) {
	var rapp []App
	for _, cs := range c {
		var match bool
		var app App
		for i := 0; i < len(cs.Fingerprints); i++ {
			fp := &cs.Fingerprints[i]
			filename := filepath.Join(dir, fp.File)
			//			err := cutils.MD5FileByC(filename)
			_, err := os.Stat(filename)
			//var hash string
			if os.IsNotExist(err) {
				continue
			}
			if !fileContains(filename, fp.Signature) {
				continue
			}
			if fileContains(filename, fp.Exclude) {
				continue
			}
			match = true
			break
		}
		if !match {
			continue
		}

		var ver string
		for i := 0; i < len(cs.Versions); i++ {
			pv := &cs.Versions[i]
			filename := filepath.Join(dir, pv.File)
			f, err := os.Open(filename)
			if os.IsNotExist(err) {
				continue
			} else if err != nil {
				fmt.Println(filename, err)
				continue
			}
			defer f.Close()

			m, err := mmap.Map(f, mmap.RDONLY, 0)
			if err != nil {
				fmt.Println("MMAP:", filename, err)
				continue
			}
			if pv.excludeExp != nil && pv.excludeExp.Match(m) {
				continue
			}

			if pv.exp != nil {
				matched := pv.exp.FindAllSubmatchIndex(m, 1)
				if len(matched) > 0 {
					start := matched[0][1]
					end := matched[0][2]
					ver = string(m[start:end])
				}
			}
			if pv.FlatFile {
				matched := flatVersionExp.FindAllSubmatchIndex(m, -1)
				for i := 0; i < len(matched); i++ {
					start := matched[i][1]
					end := matched[i][2]
					if end > start {
						ver = string(m[start:end])
						break
					}
				}
			}

			if ver != "" {
				if pv.filterExp != nil {
					ver = pv.filterExp.ReplaceAllString(ver, ".")
				}
				ver = subNextLineExp.ReplaceAllString(ver, "")
				ver = subSpaceExp.ReplaceAllString(ver, "")
				break
			}
		}
		app.Version = ver
		app.Name = cs.Name

		rapp = append(rapp, app)
	}

	return rapp, nil
}
