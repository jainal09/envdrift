# 🔐 Galileo Repository Security Scan Report

**Generated:** 2026-01-08 11:16:35  
**Scanned Directory:** `/home/jainal09/Galileo`  
**Scan Duration:** 553.9 seconds (9.2 minutes)

---

## 📊 Executive Summary

| Metric | Value |
|--------|-------|
| **Total Findings** | 1,438 |
| **Unique Findings** | 1,418 |
| **🔴 Critical** | 70 |
| **🟠 High** | 1,348 |
| **🟡 Medium** | 0 |
| **Git History Secrets** | 302 |
| **Current File Secrets** | 1,116 |

### Scanners Used
- `native` - Built-in pattern matching
- `trufflehog` - 800+ secret detectors with git history scanning
- `detect-secrets` - Yelp's secret detection tool

---

## 🕒 Git History Findings (302 secrets in past commits)

These secrets were committed to git history and may still be exposed even if removed from current files.

| # | File | Secret Type | Commit | Author | Preview |
|---|------|-------------|--------|--------|---------|
| 1 | `synapse/k8s/chart/env-values.yaml` | SendGrid | `ff01d702` | Azib Hassan | `SG.2*********************...` |
| 2 | `synapse/azure-pipelines-synapse.yml` | Dockerhub | `246a8f9c` | Jainal Gosaliya | `bbe5*********************...` |
| 3 | `stream-monitor/.env.production` | Box | `c602807a` | jainal gosaliya | `Rbse*********************...` |
| 4 | `simulator/azure-pipelines-simulator.yml` | Dockerhub | `1a8c9c8a` | Azib Hassan | `4198*********************...` |
| 5 | `redpanda/azure-pipelines-redpanda.yml` | Dockerhub | `ff01d702` | Azib Hassan | `8488*********************...` |
| 6 | `proxy-ingress/azure-pipelines-proxy-ingr` | Dockerhub | `aed0680c` | Azib Hassan | `8962*********************...` |
| 7 | `proxy-ingress/azure-pipelines-proxy-ingr` | Dockerhub | `f6dd0853` | Andy Xie | `8962*********************...` |
| 8 | `prime-daq/azure-pipelines-prime-daq.yml` | Dockerhub | `c5de0ece` | Yelena Sergeyev | `7738*********************...` |
| 9 | `portainer/azure-pipelines-portainer.yml` | Dockerhub | `ff01d702` | Azib Hassan | `bd6d*********************...` |
| 10 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 11 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 12 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 13 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 14 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 15 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 16 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 17 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 18 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 19 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 20 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 21 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 22 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 23 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 24 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 25 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 26 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 27 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 28 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 29 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 30 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 31 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 32 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 33 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 34 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 35 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 36 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 37 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 38 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 39 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 40 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 41 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 42 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 43 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 44 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 45 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 46 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 47 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 48 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 49 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 50 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 51 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 52 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 53 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 54 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 55 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 56 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 57 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 58 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 59 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 60 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 61 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 62 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 63 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 64 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 65 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 66 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 67 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 68 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 69 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 70 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 71 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 72 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 73 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 74 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 75 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 76 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 77 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 78 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 79 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 80 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 81 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 82 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 83 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 84 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 85 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 86 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 87 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 88 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 89 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 90 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 91 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 92 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 93 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 94 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 95 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 96 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 97 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 98 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 99 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 100 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 101 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 102 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 103 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 104 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 105 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 106 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 107 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 108 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 109 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 110 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 111 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 112 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 113 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 114 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 115 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 116 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 117 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 118 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 119 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 120 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 121 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 122 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 123 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 124 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 125 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 126 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 127 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 128 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 129 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 130 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 131 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 132 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 133 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 134 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 135 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 136 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 137 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 138 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 139 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 140 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 141 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 142 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 143 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 144 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 145 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 146 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 147 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 148 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 149 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 150 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 151 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 152 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 153 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 154 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 155 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 156 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 157 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 158 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 159 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 160 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 161 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 162 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 163 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 164 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 165 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 166 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 167 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 168 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 169 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 170 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 171 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 172 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 173 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 174 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 175 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 176 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 177 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 178 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 179 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 180 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 181 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 182 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 183 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 184 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 185 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 186 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 187 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 188 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 189 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 190 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 191 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 192 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 193 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 194 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 195 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 196 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 197 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 198 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 199 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 200 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 201 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 202 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 203 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 204 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 205 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 206 | `perf-metrics/k6/soak-test-script.js` | JWT | `a553c05b` | Victor Karani | `eyJh*********************...` |
| 207 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 208 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 209 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 210 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 211 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 212 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 213 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 214 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 215 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 216 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 217 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 218 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 219 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 220 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 221 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 222 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 223 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 224 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 225 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 226 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 227 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 228 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 229 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 230 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 231 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 232 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 233 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 234 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 235 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 236 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 237 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 238 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 239 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 240 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 241 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 242 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 243 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 244 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 245 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 246 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 247 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 248 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 249 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 250 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 251 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 252 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 253 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 254 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 255 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 256 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 257 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 258 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 259 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 260 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 261 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 262 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 263 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 264 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 265 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 266 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 267 | `perf-metrics/k6/k6-studio-soak-test.js` | JWT | `61dc6d89` | donrobertson | `eyJh*********************...` |
| 268 | `notifier/azure-pipelines-notifier.yml` | Dockerhub | `f6dd0853` | Andy Xie | `140f*********************...` |
| 269 | `keycloak/azure-pipelines-keycloak.yml` | Dockerhub | `ff01d702` | Azib Hassan | `4948*********************...` |
| 270 | `keycloak-wrapper/azure-pipelines-keycloa` | Dockerhub | `9d922ec2` | Peter Epstein | `e93c*********************...` |
| 271 | `kafka/azure-pipelines-kafka.yml` | Dockerhub | `ca1e12b2` | Andy Xie | `dd97*********************...` |
| 272 | `event-bus/azure-pipelines-event-bus.yml` | Dockerhub | `aed0680c` | Azib Hassan | `a98e*********************...` |
| 273 | `event-bus/azure-pipelines-event-bus.yml` | Dockerhub | `f6dd0853` | Andy Xie | `a98e*********************...` |
| 274 | `env-files/soak-machine-68.157/.env.soak.` | AzureStorage | `ff12ae64` | jgosaliya | `BJxU*********************...` |
| 275 | `env-files/soak-machine-68.157/.env.soak` | AzureStorage | `44103090` | jgosaliya | `BCVY*********************...` |
| 276 | `env-files/local/.env.local` | AzureStorage | `0b60bb1f` | jgosaliya | `BJ7b*********************...` |
| 277 | `env-files/local-machine/.env.localenv.se` | AzureStorage | `ff12ae64` | jgosaliya | `BKSL*********************...` |
| 278 | `env-files/local-machine/.env.localenv` | AzureStorage | `b6c2d829` | jainal gosaliya | `BNXT*********************...` |
| 279 | `env-files/local-machine/.env.localenv` | AzureStorage | `44103090` | jgosaliya | `BNK9*********************...` |
| 280 | `documentation/azure-pipelines-documentat` | Dockerhub | `67c22bb5` | Andy Xie | `a98e*********************...` |
| 281 | `datastore/azure-pipelines-datastore.yml` | Dockerhub | `7da22288` | Andy Xie | `0b7c*********************...` |
| 282 | `data-api/src/DataApi.Solution/DataApi.Se` | SQLServer | `dc88daa6` | Enrico Quintana | `*****...` |
| 283 | `data-api/azure-pipelines-data-api.yml` | Dockerhub | `2b814cb2` | Andy Xie | `26ac*********************...` |
| 284 | `data-api/azure-pipelines-data-api.yml` | Dockerhub | `004d26d8` | Felipe Oliveira | `26ac*********************...` |
| 285 | `daq-opc-ua/azure-pipelines-daq-opc-ua.ym` | Dockerhub | `f6dd0853` | Andy Xie | `a279*********************...` |
| 286 | `daq-dnp3/azure-pipelines-daq-dnp3.yml` | Dockerhub | `f6dd0853` | Andy Xie | `9f88*********************...` |
| 287 | `azure-pipelines.yml` | Dockerhub | `1a8c9c8a` | Azib Hassan | `23db*********************...` |
| 288 | `azure-pipelines.yml` | Dockerhub | `1a8c9c8a` | Azib Hassan | `4198*********************...` |
| 289 | `azure-pipelines.yml` | Dockerhub | `ff01d702` | Azib Hassan | `4383*********************...` |
| 290 | `azure-pipelines.yml` | Dockerhub | `ff01d702` | Azib Hassan | `8488*********************...` |
| 291 | `azure-pipelines.yml` | Dockerhub | `ff01d702` | Azib Hassan | `bd6d*********************...` |
| 292 | `azure-pipelines.yml` | Dockerhub | `c5de0ece` | Yelena Sergeyev | `7738*********************...` |
| 293 | `azure-pipelines.yml` | Dockerhub | `ff01d702` | Azib Hassan | `4948*********************...` |
| 294 | `azure-pipelines.yml` | Dockerhub | `7da22288` | Andy Xie | `8962*********************...` |
| 295 | `azure-pipelines.yml` | Dockerhub | `f37f5cb5` | Andy Xie | `8962*********************...` |
| 296 | `azure-pipelines.yml` | Dockerhub | `f37f5cb5` | Andy Xie | `a98e*********************...` |
| 297 | `azure-pipelines.yml` | Dockerhub | `246a8f9c` | Jainal Gosaliya | `8962*********************...` |
| 298 | `azure-pipelines.yml` | Dockerhub | `246a8f9c` | Jainal Gosaliya | `a98e*********************...` |
| 299 | `azure-pipelines.yml` | Dockerhub | `f6dd0853` | Andy Xie | `8962*********************...` |
| 300 | `azure-pipelines.yml` | Dockerhub | `f6dd0853` | Andy Xie | `a98e*********************...` |
| 301 | `analytics/azure-pipelines-analytics.yml` | Dockerhub | `2b814cb2` | Andy Xie | `de3d*********************...` |
| 302 | `analytics/azure-pipelines-analytics.yml` | Dockerhub | `7f057f1f` | Yelena Sergeyev | `de3d*********************...` |


### Git History Summary by Secret Type

- **JWT**: 258 occurrences
- **Dockerhub**: 35 occurrences
- **AzureStorage**: 6 occurrences
- **SendGrid**: 1 occurrences
- **Box**: 1 occurrences
- **SQLServer**: 1 occurrences


---

## 🔐 Production Environment Files

These are `.env` files and key files containing sensitive configuration.


### 📄 `env-files/local-machine/.env.localenv.secret`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 45 |

**Findings:**
- Line 89: **Generic Secret** - `********`
- Line 87: **Generic Secret** - `********`
- Line 85: **Generic Secret** - `66db****************************750`
- Line 81: **Generic Secret** - `D0bl**023!`
- Line 78: **Generic Secret** - `Dobl*123!`
- *... and 40 more findings*

### 📄 `env-files/soak-machine-68.157/.env.soak.secret`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 44 |

**Findings:**
- Line 84: **Generic Secret** - `66db****************************750`
- Line 80: **Generic Secret** - `D0bl**023!`
- Line 78: **Generic Secret** - `Dobl*123!`
- Line 74: **Generic Secret** - `Dobl*123!`
- Line 69: **Generic Secret** - `Dobl*123!`
- *... and 39 more findings*

### 📄 `synapse/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 3 |

**Findings:**
- Line 18: **Generic Secret** - `e6e8*******************************`
- Line 15: **Generic Secret** - `7851*******************************`
- Line None: **Unencrypted Environment File** - ``

### 📄 `env-files/soak-machine-68.157/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |

**Findings:**
- Line 9: **Generic Secret** - `b780*******************************`
- Line None: **Unencrypted Environment File** - ``

### 📄 `env-files/local-machine/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 2 |

**Findings:**
- Line 9: **Generic Secret** - `2649*******************************`
- Line None: **Unencrypted Environment File** - ``

### 📄 `synapse/tests/.env.test`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `synapse/.env.production.secret`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line 5: **Generic Secret** - `02d8*******************************`

### 📄 `synapse/.env.production.clear`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `synapse/.env.localenv.secret`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line 5: **Generic Secret** - `0235*******************************`

### 📄 `synapse/.env.localenv.clear`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `stream-monitor/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `simulator/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `simulator-postgres-container-support/synapse/tests/.env.test`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `simulator-postgres-container-support/perf-metrics/services/grafana-prometheus-containers/grafana/grafana.env`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line 2: **Generic Secret** - `Dobl*123!`

### 📄 `simulator-postgres-container-support/grafana/grafana.env`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line 5: **Generic Secret** - `${MA***************ORD}`

### 📄 `perf-metrics/services/grafana-prometheus-containers/grafana/grafana.env`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line 2: **Generic Secret** - `Dobl*123!`

### 📄 `grafana/grafana.env`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line 5: **Generic Secret** - `${MA***************ORD}`

### 📄 `env-files/soak-machine-68.157/.env.soak.clear`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `env-files/local-machine/.env.localenv.clear`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `axiom/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``

### 📄 `analytics/.env.keys`

| Severity | Count |
|----------|-------|
| 🔴 Critical | 0 |
| 🟠 High | 1 |

**Findings:**
- Line None: **Unencrypted Environment File** - ``


---

## 🔑 Secret Types Detected

| Count | Secret Type | Severity |
|-------|-------------|----------|
| 1,005 | Generic Secret | 🟠 HIGH |
| 258 | JWT | 🟠 HIGH |
| 35 | Dockerhub | 🟠 HIGH |
| 27 | AWS Access Key ID | 🔴 CRITICAL |
| 13 | Unencrypted Environment File | 🟠 HIGH |
| 12 | PostgreSQL Connection String | 🟠 HIGH |
| 8 | GitHub Personal Access Token | 🔴 CRITICAL |
| 8 | Generic API Key | 🟠 HIGH |
| 6 | AzureStorage | 🟠 HIGH |
| 5 | RSA Private Key | 🔴 CRITICAL |
| 4 | GitHub App Token | 🔴 CRITICAL |
| 4 | Redis Connection String | 🟠 HIGH |
| 3 | Private Key | 🔴 CRITICAL |
| 3 | EC Private Key | 🔴 CRITICAL |
| 3 | OpenSSH Private Key | 🔴 CRITICAL |
| 3 | Stripe Secret Key | 🔴 CRITICAL |
| 3 | MySQL Connection String | 🟠 HIGH |
| 2 | NPM Access Token | 🔴 CRITICAL |
| 2 | SendGrid API Key | 🔴 CRITICAL |
| 2 | Google API Key | 🔴 CRITICAL |
| 2 | Stripe Restricted API Key | 🔴 CRITICAL |
| 2 | GitLab Personal Access Token | 🔴 CRITICAL |
| 2 | GitHub OAuth Access Token | 🔴 CRITICAL |
| 1 | PGP Private Key Block | 🔴 CRITICAL |
| 1 | DSA Private Key | 🔴 CRITICAL |
| 1 | SendGrid | 🟠 HIGH |
| 1 | Box | 🟠 HIGH |
| 1 | MongoDB Connection String | 🟠 HIGH |
| 1 | SQLServer | 🟠 HIGH |


---

## 📊 Findings by Scanner

| Scanner | Critical | High | Medium | Total |
|---------|----------|------|--------|-------|
| **native** | 70 | 1046 | 0 | 1116 |
| **trufflehog** | 0 | 302 | 0 | 302 |


---

## 📁 Top Files by Finding Count

| File | Critical | High | Total |
|------|----------|------|-------|
| `envdrift/tests/unit/test_cli.py` | 0 | 53 | 53 |
| `env-files/local-machine/.env.localenv.secret` | 0 | 45 | 45 |
| `env-files/soak-machine-68.157/.env.soak.secre` | 0 | 44 | 44 |
| `envdrift/.pytest_cache/v/cache/nodeids` | 16 | 15 | 31 |
| `envdrift/tests/scanner/test_patterns.py` | 19 | 8 | 27 |
| `envdrift/tests/scanner/test_native.py` | 16 | 5 | 21 |
| `envdrift/tests/unit/test_vault_hashicorp.py` | 0 | 20 | 20 |
| `templates/jobs/vm-deploy.yml` | 0 | 18 | 18 |
| `vm-deploy.yml` | 0 | 18 | 18 |
| `web-app/frontend/src/services/apiservice_v2.t` | 0 | 12 | 12 |
| `auth.py` | 0 | 12 | 12 |
| `apiservice_v2.ts` | 0 | 12 | 12 |
| `envdrift/tests/conftest.py` | 1 | 10 | 11 |
| `postgresql-env.sh` | 0 | 11 | 11 |
| `libpostgresql.sh` | 0 | 11 | 11 |
| `postgresql-env.sh` | 0 | 11 | 11 |
| `libpostgresql.sh` | 0 | 11 | 11 |
| `helm-deploy.yml` | 0 | 9 | 9 |
| `envdrift/tests/unit/test_vault_aws.py` | 0 | 9 | 9 |
| `envdrift/tests/unit/test_smart_encryption.py` | 0 | 9 | 9 |
| `datastore/templates/steps/helm-deploy.yml` | 0 | 9 | 9 |
| `envdrift/src/envdrift/scanner/patterns.py` | 6 | 2 | 8 |
| `web-app/frontend/src/composables/useAlerts.ts` | 0 | 8 | 8 |
| `useAlerts.ts` | 0 | 8 | 8 |
| `EventType.cs` | 0 | 8 | 8 |
| `EventType.cs` | 0 | 8 | 8 |
| `envdrift/tests/unit/test_validator.py` | 1 | 6 | 7 |
| `web-app/backend/src/Helpers/PageContextHelper` | 0 | 7 | 7 |
| `PageContextHelper.cs` | 0 | 7 | 7 |
| `init.sh` | 0 | 7 | 7 |


---

## 🚨 Critical Findings Detail


### 🔴 AWS Access Key ID (27 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_validator.py` | 209 | `AKIA************MPLE` | native |
| `test_trufflehog.py` | 815 | `AKIA************MPLE` | native |
| `test_trufflehog.py` | 384 | `AKIA************MPLE` | native |
| `test_patterns.py` | 165 | `AKIA************MPLE` | native |
| `test_patterns.py` | 156 | `AKIA************MPLE` | native |
| `test_patterns.py` | 154 | `AKIA************MPLE` | native |
| `test_patterns.py` | 25 | `ASIA************1234` | native |
| `test_patterns.py` | 24 | `AKIA************MPLE` | native |
| `test_native.py` | 460 | `AKIA************MPLE` | native |
| `test_native.py` | 448 | `AKIA************MPLE` | native |

*... and 17 more*

### 🔴 GitHub Personal Access Token (8 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_trufflehog.py` | 435 | `ghp_*********************` | native |
| `test_patterns.py` | 27 | `ghp_*********************` | native |
| `test_native.py` | 450 | `ghp_*********************` | native |
| `test_native.py` | 387 | `ghp_*********************` | native |
| `test_native.py` | 205 | `ghp_*********************` | native |
| `test_gitleaks.py` | 394 | `ghp_*********************` | native |
| `test_engine.py` | 542 | `ghp_*********************` | native |
| `nodeids` | 237 | `ghp_*********************` | native |

### 🔴 RSA Private Key (5 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 42 | `----*********************` | native |
| `test_native.py` | 217 | `----*********************` | native |
| `test_encryption_edge_cases.py` | 124 | `----*********************` | native |
| `patterns.py` | 253 | `----*********************` | native |
| `nodeids` | 231 | `----*********************` | native |

### 🔴 GitHub App Token (4 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 30 | `ghs_*********************` | native |
| `test_patterns.py` | 29 | `ghu_*********************` | native |
| `nodeids` | 239 | `ghu_*********************` | native |
| `nodeids` | 238 | `ghs_*********************` | native |

### 🔴 Private Key (3 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 45 | `----*******************--` | native |
| `patterns.py` | 277 | `----*******************--` | native |
| `nodeids` | 230 | `----*******************--` | native |

### 🔴 EC Private Key (3 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 44 | `----*********************` | native |
| `patterns.py` | 265 | `----*********************` | native |
| `nodeids` | 228 | `----*********************` | native |

### 🔴 OpenSSH Private Key (3 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 43 | `----*********************` | native |
| `patterns.py` | 259 | `----*********************` | native |
| `nodeids` | 229 | `----*********************` | native |

### 🔴 Stripe Secret Key (3 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 33 | `sk_l*********************` | native |
| `test_native.py` | 232 | `sk_l*********************` | native |
| `nodeids` | 243 | `sk_l*********************` | native |

### 🔴 NPM Access Token (2 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 40 | `npm_*********************` | native |
| `nodeids` | 241 | `npm_*********************` | native |

### 🔴 SendGrid API Key (2 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 38 | `SG.x*********************` | native |
| `nodeids` | 235 | `SG.x*********************` | native |

### 🔴 Google API Key (2 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 36 | `AIza*********************` | native |
| `nodeids` | 232 | `AIza*********************` | native |

### 🔴 Stripe Restricted API Key (2 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 34 | `rk_l*********************` | native |
| `nodeids` | 242 | `rk_l*********************` | native |

### 🔴 GitLab Personal Access Token (2 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 31 | `glpa******************xxx` | native |
| `nodeids` | 240 | `glpa*********************` | native |

### 🔴 GitHub OAuth Access Token (2 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `test_patterns.py` | 28 | `gho_*********************` | native |
| `nodeids` | 236 | `gho_*********************` | native |

### 🔴 PGP Private Key Block (1 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `patterns.py` | 283 | `----*********************` | native |

### 🔴 DSA Private Key (1 findings)

| File | Line | Preview | Scanner |
|------|------|---------|---------|
| `patterns.py` | 271 | `----*********************` | native |


---

## 🛠️ Remediation Recommendations

### Immediate Actions

1. **Rotate All Exposed Secrets**
   - DockerHub tokens found in git history
   - SendGrid API keys
   - JWT tokens (if still valid)
   - AWS access keys

2. **Encrypt Environment Files**
   ```bash
   cd /home/jainal09/Galileo
   envdrift encrypt env-files/local-machine/.env.localenv.secret
   envdrift encrypt synapse/.env.keys
   ```

3. **Remove Secrets from Git History**
   ```bash
   # Use git-filter-repo or BFG Repo Cleaner
   git filter-repo --invert-paths --path <sensitive-file>
   ```

### Long-term Actions

1. **Set up pre-commit hooks**
   ```bash
   envdrift guard --staged
   ```

2. **Add to CI/CD pipeline**
   ```bash
   envdrift guard --ci --fail-on high
   ```

3. **Use vault for secrets management**
   - AWS Secrets Manager
   - HashiCorp Vault
   - Azure Key Vault

---

## ⚡ Command Reference

```bash
# Full scan with history
cd /home/jainal09/Galileo/envdrift
uv run envdrift guard /home/jainal09/Galileo --history --trufflehog --detect-secrets -v

# JSON output
uv run envdrift guard /home/jainal09/Galileo --history --json > report.json

# Quick native-only scan
uv run envdrift guard /home/jainal09/Galileo --native-only
```

---

*Report generated by envdrift guard*
