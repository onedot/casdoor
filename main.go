// Copyright 2021 The Casdoor Authors. All Rights Reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package main

import (
	"fmt"

	"github.com/beego/beego/v2/core/logs"
	beego "github.com/beego/beego/v2/server/web"
	"github.com/beego/beego/v2/server/web/context"
	"github.com/beego/beego/v2/server/web/session"
	"github.com/casdoor/casdoor/authz"
	"github.com/casdoor/casdoor/conf"
	"github.com/casdoor/casdoor/ldap"
	"github.com/casdoor/casdoor/object"
	"github.com/casdoor/casdoor/proxy"
	"github.com/casdoor/casdoor/radius"
	"github.com/casdoor/casdoor/routers"
	"github.com/casdoor/casdoor/util"
)

// Global session manager instance for beego v2
var globalSessions *session.Manager

func main() {
	object.InitFlag()
	object.InitAdapter()
	object.CreateTables()

	object.InitDb()
	object.InitDefaultStorageProvider()
	object.InitLdapAutoSynchronizer()
	proxy.InitHttpClient()
	authz.InitApi()
	object.InitUserManager()
	object.InitFromFile()
	object.InitCasvisorConfig()

	util.SafeGoroutine(func() { object.RunSyncUsersJob() })

	// beego.DelStaticPath("/static")
	// beego.SetStaticPath("/static", "web/build/static")

	beego.BConfig.WebConfig.DirectoryIndex = true
	beego.SetStaticPath("/swagger", "swagger")
	beego.SetStaticPath("/files", "files")
	// https://studygolang.com/articles/2303

	// Configure session for beego v2
	beego.BConfig.WebConfig.Session.SessionOn = true
	beego.BConfig.WebConfig.Session.SessionName = "casdoor_session_id"
	beego.BConfig.WebConfig.Session.SessionAutoSetCookie = true
	beego.BConfig.WebConfig.Session.SessionGCMaxLifetime = 3600            // 1 hour
	beego.BConfig.WebConfig.Session.SessionCookieLifeTime = 3600 * 24 * 30 // 30 days

	logs.Info("Session configuration: SessionOn = %v", beego.BConfig.WebConfig.Session.SessionOn)

	if conf.GetConfigString("redisEndpoint") == "" {
		beego.BConfig.WebConfig.Session.SessionProvider = "file"
		beego.BConfig.WebConfig.Session.SessionProviderConfig = "./tmp"
		logs.Info("Using file session provider: %s", beego.BConfig.WebConfig.Session.SessionProviderConfig)
	} else {
		beego.BConfig.WebConfig.Session.SessionProvider = "redis"
		beego.BConfig.WebConfig.Session.SessionProviderConfig = conf.GetConfigString("redisEndpoint")
		logs.Info("Using redis session provider: %s", beego.BConfig.WebConfig.Session.SessionProviderConfig)
	}

	// Initialize session manager for beego v2
	if beego.BConfig.WebConfig.Session.SessionOn {
		logs.Info("Initializing session manager...")
		var err error
		sessionConfig := &session.ManagerConfig{
			CookieName:      beego.BConfig.WebConfig.Session.SessionName,
			EnableSetCookie: true,
			Gclifetime:      3600,
			Secure:          false,
			CookieLifeTime:  3600 * 24 * 30, // 30 days
			ProviderConfig:  beego.BConfig.WebConfig.Session.SessionProviderConfig,
		}

		if conf.GetConfigString("redisEndpoint") == "" {
			// Use file provider
			globalSessions, err = session.NewManager("file", sessionConfig)
		} else {
			// Use redis provider
			globalSessions, err = session.NewManager("redis", sessionConfig)
		}

		if err != nil {
			panic(fmt.Sprintf("Failed to initialize session manager: %v", err))
		}
		logs.Info("Session manager initialized successfully")
		go globalSessions.GC()

		// Add session filter to initialize sessions for each request
		beego.InsertFilter("*", beego.BeforeRouter, func(ctx *context.Context) {
			if globalSessions != nil {
				sessionStore, err := globalSessions.SessionStart(ctx.ResponseWriter, ctx.Request)
				if err == nil {
					ctx.Input.CruSession = sessionStore
				} else {
					logs.Error("Session filter: SessionStart failed: %v", err)
				}
			} else {
				logs.Warn("Session filter: globalSessions is nil")
			}
		})
		logs.Info("Session filter registered successfully")
	} else {
		logs.Warn("Session is disabled in configuration")
	}

	beego.InsertFilter("*", beego.BeforeRouter, routers.StaticFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.AutoSigninFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.CorsFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.ApiFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.PrometheusFilter)
	beego.InsertFilter("*", beego.BeforeRouter, routers.RecordMessage)
	beego.InsertFilter("*", beego.AfterExec, routers.AfterRecordMessage, beego.WithReturnOnOutput(false))

	err := logs.SetLogger(logs.AdapterFile, conf.GetConfigString("logConfig"))
	if err != nil {
		panic(err)
	}
	port := beego.AppConfig.DefaultInt("httpport", 8000)
	// logs.SetLevel(logs.LevelInformational)
	logs.SetLogFuncCall(false)

	go ldap.StartLdapServer()
	go radius.StartRadiusServer()
	go object.ClearThroughputPerSecond()

	beego.Run(fmt.Sprintf(":%v", port))
}
