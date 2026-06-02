---
name: weather-reporter
description: Fetches the current weather forecast for a named city and returns a short, human-readable summary of temperature and conditions for that location.
license: Apache-2.0
---

# Weather Reporter

This skill takes a city name as input and returns the current weather
conditions for that city. It reads from a configured weather API client
that is provided by the host application. It performs no file system,
network, or subprocess operations of its own; all data access goes through
the injected, allowlisted weather client.

## Usage

Provide a city name. The skill returns a one-line summary such as
"San Francisco: 16C, partly cloudy".
