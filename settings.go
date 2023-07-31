package main

import "os"

var (
	MOONSTREAM_ACCESS_TOKEN        = os.Getenv("MOONSTREAM_ACCESS_TOKEN")
	MOONSTREAM_API_URL             = os.Getenv("MOONSTREAM_API_URL")
	MOONSTREAM_API_TIMEOUT_SECONDS = os.Getenv("MOONSTREAM_API_TIMEOUT_SECONDS")

	BUGOUT_ACCESS_TOKEN = os.Getenv("BUGOUT_ACCESS_TOKEN")
)
