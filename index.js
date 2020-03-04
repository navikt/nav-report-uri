const express = require('express');
const bodyParser = require('body-parser');
const csp = require('content-security-policy');
const prometheus = require('prom-client');

function log (message, data) {
    const logMessage = {
        message,
        level: 'INFO'
    };
    if (data != null) {
        logMessage.data = data;
    }
    console.log(JSON.stringify(logMessage));
}

const app = express();

app.get('/nav-report-uri/health', (req, res) => res.send('ok'));

const c = new prometheus.Counter({
    name: 'reports',
    help: 'Number of reports',
    labelNames: ['directive', 'app_hostname', 'destination_type']
});

app.get('/nav-report-uri/metrics', (req, res) => {
    res.set('Content-Type', prometheus.register.contentType);
    res.end(prometheus.register.metrics());
});

app.use(bodyParser.json({ type: ['application/csp-report', 'application/json'] }));

const internalDomains = [
    'nav.no',
    'nais.io',
    'adeo.no',
    'oera.no',
    'devillo.no',
    'oera-q.local',
    'oera-t.local',
    'test.local',
    'preprod.local'
];
function classifyBlockedUri(uri) {
    if (['inline', 'data'].indexOf(uri) !== -1) {
        return uri;
    }
    try {
        const url = new URL(uri);
        if (url.hostname) {
            for (const domain of internalDomains) {
                if (url.hostname.endsWith(domain)) {
                    return domain;
                }
            }
            return 'external';
        }
    } catch (err) {
        return 'other';
    }
}

app.post('/nav-report-uri/report', (req, res) => {
    const report = req.body['csp-report'];

    c.inc({
        directive: report['violated-directive'],
        app_hostname: new URL(report['document-uri']).hostname,
        destination_type: classifyBlockedUri(report['blocked-uri'])
    });
    log('received report', req.body);
    res.send();
});

// An insanely restrictive policy - just for testing!
const localCSP = csp.getCSP({
    'report-only': true,
    'report-uri': '/nav-report-uri/report',
    'default-src': csp.SRC_NONE,
    'script-src': [csp.SRC_SELF, csp.SRC_DATA]
});

app.get('/nav-report-uri/testendpoint', localCSP, (req, res) => {
    res.header('Content-Type', 'text/html');
    res.send(`<!doctype html>
<html>
<head>
  <title>Test</title>
  <link rel=”dns-prefetch” href="evilsite.example.com">
  <link rel="prefetch" href="https://evilsite.example.com/test-prefetch" />
  <link rel="stylesheet" href="https://evilsite.example.com/test-stylesheet" />
</head>
<body>
<style>
.test-inline-style {
}
@font-face {
  font-family: 'TestFont';
  src: url('https://evilsite.example.com/test-font') format('woff2');
}
</style>
<script src="https://evilsite.devillo.no/test-script"></script>
<script>var testInlineScript = 'test-inline-script';</script>
  body
  <img src="https://evilsite.example.com/test-image" />
  <img src="https://evilsite.adeo.no/test-image-adeo" />
  <img src="data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAIAAAACACAYAAADDPmHLAAAAAXNSR0IArs4c6QAAAARnQU1BAACxjwv8YQUAAAAJcEhZcwAADsMAAA7DAcdvqGQAAAFLSURBVHhe7cgxAQAwEISwk17nXwM4gCFLtreLGGY8MOOBGQ/MeGDGAzMemPHAjAdmPDDjgRkPzHhgxgMzHpjxwIwHZjww44EZD8x4YMYDMx6Y8cCMB2Y8MOOBGQ/MeGDGAzMemPHAjAdmPDDjgRkPzHhgxgMzHpjxwIwHZjww44EZD8x4YMYDMx6Y8cCMB2Y8MOOBGQ/MeGDGAzMemPHAjAdmPDDjgRkPzHhgxgMzHpjxwIwHZjww44EZD8x4YMYDMx6Y8cCMB2Y8MOOBGQ/MeGDGAzMemPHAjAdmPDDjgRkPzHhgxgMzHpjxwIwHZjww44EZD8x4YMYDMx6Y8cCMB2Y8MOOBGQ/MeGDGAzMemPHAjAdmPDDjgRkPzHhgxgMzHpjxwIwHZjww44EZD8x4YMYDMx6Y8cCMB2Y8MOOBGQ/MeGDGAzMemJHYfQ0fxZI2fS6OAAAAAElFTkSuQmCC" />
  
  <audio controls>
    <source src="https://evilsite.nais.io/test-audio" type="audio/ogg">
  </audio>
  <video width="320" height="240" controls>
    <source src="https://evilsite.test.local/test-video" type="video/ogg">
  </video>
</body>
</html>`);
});

const port = 8080;

app.listen(port, () => {
    log(`App listening on port ${port}.`);
});
