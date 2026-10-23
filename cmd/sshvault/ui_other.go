//go:build !darwin

package main

import "github.com/crgimenes/glaze"

func configureNativeWindow(glaze.WebView) {}
func showAppError(error)                  {}
