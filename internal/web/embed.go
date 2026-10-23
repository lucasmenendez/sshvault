package web

import "embed"

// FS contains the embedded single-page application.
//
//go:embed static/*
var FS embed.FS
