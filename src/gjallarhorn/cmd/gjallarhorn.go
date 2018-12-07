// Copyright © 2018 Playground Global, LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

// Gjallarhorn scans the database for soon-to-expire certs and sends emails to affected users.
// Intended to be called as a cron job, pointed at the same database file Heimdall uses.

import (
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"

	"playground/config"
	"playground/log"
	"playground/mail"
)

func main() {
	initConfig()
	mail.Ready()
	serviceName, results, err := fetchResults()
	if err != nil {
		log.Error("main", "error fetching notification targets", err)
		return
	}

	if err = doNotifications(serviceName, results); err != nil {
		log.Error("main", "error sending notification emails", err)
		return
	}

	log.Status("main", "done")
}

type configType struct {
	Debug        bool
	DatabaseFile string
	SenderName   string
	ServiceURL   string
	Mail         *mail.ConfigType
}

var cfg = configType{
	false,
	"Gjallarhorn (Bifröst VPN Alerts)",
	"https://vpn.domain.tld/",
	"./heimdall.sqlite3",
	&mail.Config,
}

func initConfig() {
	config.Load(&cfg)
	if config.Debug || cfg.Debug {
		log.SetLogLevel(log.LEVEL_DEBUG)
	}
}

type result struct {
	Email       string
	Description string
	Fingerprint string
	Expires     time.Time
}
type resultSet struct {
	Month []*result
	Week  []*result
	Day   []*result
}

func fetchExpirations(cxn *sql.DB, window string) ([]*result, error) {
	q := "select email, desc, expires, fingerprint from certs where revoked is null and expires = date('now', 'localtime', ?)"
	rows, err := cxn.Query(q, window)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	res := []*result{}

	for rows.Next() {
		r := &result{}
		rows.Scan(&r.Email, &r.Description, &r.Expires, &r.Fingerprint)
		res = append(res, r)
	}

	return res, nil
}

func fetchResults() (string, map[string]*resultSet, error) {
	res := make(map[string]*resultSet)

	cxn, err := sql.Open("sqlite3", cfg.DatabaseFile)
	if err != nil {
		return "", nil, err
	}
	defer cxn.Close()

	setDefault := func(email string, mrs *map[string]*resultSet) *resultSet {
		rs, ok := (*mrs)[email]
		if !ok {
			rs = &resultSet{[]*result{}, []*result{}, []*result{}}
			(*mrs)[email] = rs
		}
		return rs
	}

	results, err := fetchExpirations(cxn, "+30 days")
	if err != nil {
		return "", nil, err
	}
	for _, r := range results {
		rs := setDefault(r.Email, &res)
		rs.Month = append(rs.Month, r)
	}

	results, err = fetchExpirations(cxn, "+7 days")
	if err != nil {
		return "", nil, err
	}
	for _, r := range results {
		rs := setDefault(r.Email, &res)
		rs.Week = append(rs.Week, r)
	}

	results, err = fetchExpirations(cxn, "+1 days")
	if err != nil {
		return "", nil, err
	}
	for _, r := range results {
		rs := setDefault(r.Email, &res)
		rs.Day = append(rs.Day, r)
	}

	rows, err := cxn.Query("select value from settings where key='ServiceName'")
	if err != nil {
		return "", nil, err
	}
	defer rows.Close()
	if !rows.Next() {
		return "", nil, errors.New("missing ServiceName in settings table")
	}
	var s string
	rows.Scan(&s)

	return s, res, nil
}

func doNotifications(serviceName string, results map[string]*resultSet) error {
	type payload struct{ Recipients, SenderName, Sender, ServiceName, URL, When, List string }

	for email, set := range results {
		if len(set.Month) > 0 {
			t := cfg.Mail.Templates[0]
			descs := []string{}
			for _, r := range set.Month {
				descs = append(descs, r.Description)
			}
			when := set.Month[0].Expires.Format("Monday, 2 January, 2006")
			list := strings.Join(descs, "\n")
			p := payload{email, cfg.SenderName, t.SenderEmail, serviceName, cfg.ServiceURL, when, list}
			if err := mail.Send(t.Name, []string{email}, p); err != nil {
				log.Warn("doNotifications", fmt.Sprintf("error sending mail to '%s'", email), err)
			}
		}

		if len(set.Week) > 0 {
			t := cfg.Mail.Templates[1]
			descs := []string{}
			for _, r := range set.Week {
				descs = append(descs, r.Description)
			}
			when := set.Week[0].Expires.Format("Monday, 2 January, 2006")
			list := strings.Join(descs, "\n")
			p := payload{email, cfg.SenderName, t.SenderEmail, serviceName, cfg.ServiceURL, when, list}
			if err := mail.Send(t.Name, []string{email}, p); err != nil {
				log.Warn("doNotifications", fmt.Sprintf("error sending mail to '%s'", email), err)
			}
		}

		if len(set.Day) > 0 {
			t := cfg.Mail.Templates[2]
			descs := []string{}
			for _, r := range set.Day {
				descs = append(descs, r.Description)
			}
			when := set.Day[0].Expires.Format("Monday, 2 January, 2006")
			list := strings.Join(descs, "\n")
			p := payload{email, cfg.SenderName, t.SenderEmail, serviceName, cfg.ServiceURL, when, list}
			if err := mail.Send(t.Name, []string{email}, p); err != nil {
				log.Warn("doNotifications", fmt.Sprintf("error sending mail to '%s'", email), err)
			}
		}
	}

	return nil
}
