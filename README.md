
Designed for use in Bitbucket as a scanning pipe, but is really just a generic wrapper

# USAGE

```bash
scan-app: &scan-app
 - step:
     name: "Scan for vulnerabilities, malware and embedded secrets""
     caches:
       - node
     script:
       - pipe: docker://docker.io/TrendAndrew/trend-scan:1.0
         variables:
           TMAS_API_KEY: $TMAS_API_KEY
           FLAGS: "--vulnerabilities --malware --secrets"
```

# TESTING
```bash
docker run -e TMAS_API_KEY="test" -it TrendAndrew/trend-scan scan --vulnerabilities --malware --secrets
```

ref: https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-artifact-scanner-cli

