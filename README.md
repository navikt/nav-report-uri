![Build, push, and deploy](https://github.com/navikt/nav-report-uri/workflows/Build,%20push,%20and%20deploy/badge.svg)

# NAV Report URI tool

This application listens for [CSP](https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP) violation reports on `/nav-report-uri/report`
and forwards them to Kibana and Prometheus.

### Development

`npm install`

Starting the server: `node index.js`

It will listen on http://localhost:8080.

Open a browser on `http://localhost:8080/nav-report-uri/testendpoint`, which
will try to load CSS, images, fonts, audio etc. from "illegal" URLs. That
will lead to reports in the logs, and increased Prometheus counters.

### Prometheus

The app will expose statistics on `http://localhost:8080/nav-report-uri/metrics`.


