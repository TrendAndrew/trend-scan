# Trend Micro Artifact Scanner (TMAS)

## Description

The Trend Micro Artifact Scanner (`tmas`) CLI tool performs pre-runtime vulnerability, malware, and secret scans on artifacts (see [Supported artifacts](#supported-artifacts)), enabling you to identify and fix issues before they reach a production environment, like Kubernetes for container images, for example. Additionally, you can scan LLM endpoints for security vulnerabilities to identify risks to your AI Applications (see [#aiscan-command-usage](#aiscan-command-usage)).

Further documentation can be found [here](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-tmas-about)

## Download and install

You can check the latest version via [metadata.json](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/metadata.json)

| Architecture                                                                                                                               |
| ------------------------------------------------------------------------------------------------------------------------------------------ |
| [Darwin_arm64](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Darwin_arm64.zip) (MacOS - Apple Silicon chipset) |
| [Darwin_x86_64](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Darwin_x86_64.zip) (MacOS - Intel chipset)       |
| [Linux_arm64](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Linux_arm64.tar.gz)                                |
| [Linux_i386](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Linux_i386.tar.gz)                                  |
| [Linux_x86_64](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Linux_x86_64.tar.gz)                              |
| [Windows_arm64](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Windows_arm64.zip)                               |
| [Windows_i386](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Windows_i386.zip)                                 |
| [Windows_x86_64](https://cli.artifactscan.cloudone.trendmicro.com/tmas-cli/latest/tmas-cli_Windows_x86_64.zip)                             |

## System requirements

The following minimum system requirements are sufficient to scan most artifacts.

Your system must have enough storage capacity to accommodate the size of your target artifact. For images, your system must have sufficient space for its uncompressed size.

Memory consumption of the TMAS CLI scales with the number of files an artifact contains. Some artifacts may require additional memory to complete successfully. Performance can be improved by increasing memory resources and CPU cores.

| Hardware | Minimum | Recommended |
| -------- | ------- | ----------- |
| Storage  | 16 GB   | 16 GB       |
| Ram      | 2 GB    | 4 GB        |
| vCPU     | 1       | 1           |

## Upgrading to the latest version of the TMAS CLI

To ensure optimal performance and access to the latest features, it is recommended to upgrade to the most recent version of TMAS on a regular basis.

1. **Download the Updated Binary**: Navigate to the [**Download and install**](#download-and-install) section to locate the download links for the latest version of the TMAS CLI.

2. **Adjust your system's binary path settings**: Replace the existing TMAS binary with the updated TMAS binary. For information, see **Add TMAS CLI to your PATH** under the [Setup](#setup) section.

TMAS is now successfully updated to the latest version.

## Setup

The CLI requires a valid API key to be stored in the environment variable. It is able to accept either a Trend Vision One API key or a Trend Cloud One API key. Please add the API Key associated with the Trend Vision One or Trend Cloud One region that you wish to call as an environment variable named `TMAS_API_KEY`.

Example:

```
export TMAS_API_KEY=<your_vision_one_api_key>
```

```
export TMAS_API_KEY=<your_cloud_one_api_key>
```

When obtaining the API Key, ensure that the API Key is associated with the region that you plan to use. It is important to note that Trend Vision One API Keys and Trend Cloud One API Keys are associated with different regions, please refer to the region flag below to obtain a better understanding of the valid regions associated with the respective API Key.

For instance, if you plan on using the default Trend Vision One region, you would create a Trend Vision One API Key for the Trend Vision One us-east-1 region. If you plan on using a Trend Cloud One region or a different Trend Vision One region, be sure to use the `--region` flag when running TMAS to specify the region of that API key and to ensure you have proper authorization. The list of supported Trend Vision One and Trend Cloud One regions can be found under the region flag.

**Obtain a Trend Vision One API key:**

1. Log in to the [Trend Vision One Console](https://portal.xdr.trendmicro.com/).
2. Create a new Trend Vision One API key:
   - Navigate to the [Trend Vision One User Roles page](https://portal.xdr.trendmicro.com/#/app/iam2/role).<br>
   - Verify that there is a role with the **Run artifact scan** permissions enabled. If not, create a role by clicking on **Add Role** and **Save** once finished.
   - Directly configure a new key on the [Trend Vision One API Keys page](https://portal.xdr.trendmicro.com/#/app/iam2/apikey), using the role which contains the **Run artifacts scan** permission. Set an expiry time for the API key and keep a record of it for future reference.

When obtaining the API key, ensure that the API key is associated with the endpoint you are calling. For instance, create an API key for the `us-east-1` region if you are planning to call the `us-east-1` endpoint to ensure proper authorization.

You can manage these keys from the [Trend Vision One API Keys Page](https://portal.xdr.trendmicro.com/#/app/iam2/apikey).

**Obtain a Trend Cloud One API key:**

Option 1: Generate a new key through the [Trend Cloud One Container Security scanners page](https://cloudone.trendmicro.com/container/scanners)

Option 2: Directly configure a new key on [Trend Cloud One API-Keys page](https://cloudone.trendmicro.com/administration/api-keys)

1. Log in to the [Trend Cloud One console](https://cloudone.trendmicro.com/home).
2. Create a pipeline scanner role for your Trend Cloud One Account [here](https://cloudone.trendmicro.com/administration/roles).
   - Click "New"
   - Set Name, ID, and Description for your role, we recommend setting Name to "Scanner" and ID to "scanner"
   - Under Privileges select "Container Security" as your Service and "Scanner" as your Permission
3. Create your API Key [here](https://cloudone.trendmicro.com/administration/api-keys) using the new Role you have created in step 2

When obtaining the API Key, ensure that the API Key is associated with the region that you plan to use. For instance, create an API Key for the `us-1` region if you are planning to invoke the `us-1` endpoint. If using a Trend Cloud One API Key, use the `--region` flag when running TMAS to specify the region of that API key and to ensure you have proper authorization.

**Add tmas CLI to your PATH:**

```sh
export PATH="/path/to/tmas/binary/directory:$PATH"
```

## General usage

```sh
tmas [command] [flags]
```

### Available commands

| Command   | Description                                                                                               |
| --------- | --------------------------------------------------------------------------------------------------------- |
| `scan`    | Scan an artifact with any combination of scanners (at least one of vulnerabilities, malware, or secrets). |
| `aiscan`  | Scan an AI Application for vulnerabilities                                                                |
| `version` | Get the current CLI version (long).                                                                       |
| `help`    | Display help information.                                                                                 |

### Global flags

| Flag            | Description                                  |
| --------------- | -------------------------------------------- |
| `--version`     | Get the current CLI version (short).         |
| `-v, --verbose` | Increase verbosity (-v = info, -vv = debug). |
| `-h, --help`    | Display help information.                    |

## Scan command usage

```sh
tmas scan [artifact] [flags]
```

### Scan command flags

| Flag                    | Description                                                                                                                                                                                                                                                                                          |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-p, --platform`        | Specify platform for multi-platform container image sources (optional).<br>For example: 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux' (default 'linux/amd64').                                                                                                                                   |
| `-r, --region`          | Trend Vision One service regions: [ap-southeast-2 eu-central-1 ap-south-1 ap-northeast-1 ap-southeast-1 me-central-1 us-east-1], Trend Cloud One service regions: [au-1 ca-1 de-1 gb-1 in-1 jp-1 sg-1 us-1] (default is set to Vision One region "us-east-1")                                        |
| `-V, --vulnerabilities` | Enable scanning for vulnerabilities (optional).                                                                                                                                                                                                                                                      |
| `-M, --malware`         | Enable scanning for malware (optional). Supports `docker`, `docker-archive`, `oci-archive`, `oci-dir` and `registry` artifact types.                                                                                                                                                                 |
| `-S, --secrets`         | Enable scanning for secrets (optional).                                                                                                                                                                                                                                                              |
| `--saveSBOM`            | Save SBOM in the local directory, when the vulnerability scanner is enabled (optional).                                                                                                                                                                                                              |
| `--distro`              | Specify the distribution to match vulnerabilities against file and directory artifacts (optional).<br>Use the formation \<distro\>:\<version\>, like `ol:8.4`, for example.                                                                                                                          |
| `-o, --override`        | Specify the file path to the file containing the vulnerability and secret override rules (optional).<br>For example: `/path/to/tmas_overrides.yml`.                                                                                                                                                  |
| `--redacted`            | Redact secrets in the secrets finding report in the TMAS CLI output. This will remove sensitive information from the report, such as passwords, tokens, and other sensitive data. Secret findings are always redacted prior to being sent to Trend Micro's servers, regardless of this flag's state. |
| `--evaluatePolicy`      | Evaluate the scan results against the Vision One Code Security policy. TMAS will return the results and exit with status code '2' if the policy is violated.                                                                                                                                         |
| `-v, --verbose`         | Increase verbosity (-v = info, -vv = debug).                                                                                                                                                                                                                                                         |
| `-h, --help`            | Display help information.                                                                                                                                                                                                                                                                            |

_Note:_ For more information on available scanners and their flags, see [Scan subcommands](#scan-subcommands). Using a scanner-specific flag without enabling the associated scanner does not result in an error, but that flag does have no effect.

<a name="supported Artifacts"></a>

### Supported artifacts

| Artifact                               | Description                                                                              |
| -------------------------------------- | ---------------------------------------------------------------------------------------- |
| `docker:yourrepo/yourimage:tag`        | Use images from the Docker daemon.                                                       |
| `podman:yourrepo/yourimage:tag`        | Use images from the Podman daemon.                                                       |
| `docker-archive:path/to/yourimage.tar` | Use a tarball from disk for archives created from docker save.                           |
| `oci-archive:path/to/yourimage.tar`    | Use a tarball from disk for OCI archives (from Skopeo or otherwise).                     |
| `oci-dir:path/to/yourimage`            | Read directly from a path on disk for OCI layout directories (from Skopeo or otherwise). |
| `singularity:path/to/yourimage.sif`    | Read directly from a Singularity Image Format (SIF) container on disk.                   |
| `registry:yourrepo/yourimage:tag`      | Pull image directly from a registry (no container runtime required).                     |
| `dir:path/to/yourproject`              | Read directly from a path on disk (any directory).                                       |
| `file:path/to/yourproject/file`        | Read directly from a path on disk (any single file).                                     |

## Scan examples

**Scanning an artifact for vulnerabilities, malware, and secrets**:

```sh
tmas scan <artifact_to_scan> -V -M -S
```

or

```sh
tmas scan <artifact_to_scan> -VMS
```

or

```sh
tmas scan <artifact_to_scan> --vulnerabilities --malware --secrets
```

_Note:_ When you use the `scan` command, enable at least one scanner.

**Using the region flag to switch to a different Trend Vision One or Trend Cloud One region**:

```sh
tmas scan docker:yourrepo/yourimage:tag -VMS --region=au-1
```

_Note:_ When switching to a different region, please ensure that the `TMAS_API_KEY`, which is stored as an environment variable, is associated with that Trend Vision One or Trend Cloud One region.
A mismatch causes the scan command to fail with a `403 Forbidden` or `APIKeyPlatformMismatchError` error.

**Scanning an image in a remote registry**:

```sh
tmas scan registry:yourrepo/yourimage:tag -VMS
```

Using a registry as an artifact source does not require a container runtime. In addition, scan results from registry artifact sources can be used for policy evaluations in [Trend Vision One Container Security](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-tmas-integrate).

_Note:_ Scanning images from private registries requires that you login to the registry using tools such as `docker login` before attempting the scan. TMAS follows Docker's authentication behavior in order to use Docker's pre-configured credentials. When running malware scans on images from private registries and using Docker credsStore (`.docker/config.json`), add the `credential-helpers=<your credsStore>` configuration in the `.config/containers/registries.conf` file. For example, if Docker credsStore is `desktop`, add `credential-helpers = ["desktop"]`. When running malware scans on images from private registries on Docker Hub, ensure you log in with the server name `https://docker.io` or `docker.io`. For example, `docker login docker.io`.

**Enabling info logs**:

```sh
tmas scan docker:yourrepo/yourimage:tag -VMS -v
```

**Saving SBOM used for vulnerability analysis to disk**:

```sh
tmas scan docker:yourrepo/yourimage:tag -VMS --saveSBOM
```

_Note:_ When the `--saveSBOM` flag is enabled, the generated SBOM is saved in the local directory before it is sent to Trend Cloud One for scanning.

**Using the platform flag to specify platform or architecture of container images**:

This flag allows you to specify which platform or architecture to use when scanning multiple-architecture container images:

```sh
tmas scan registry:yourrepo/yourimage:tag@sha256:<multiple-architecture-digest> -VMS --platform=arm64
```

Attempting to specify an architecture for multi-arch registry images without support for that architecture will result in an error.
When scanning architecture-specific registry images, the platform flag is ignored.

```sh
tmas scan docker:yourrepo/yourimage:tag@sha256:<arm64-specific-digest> -VMS --platform=arm64
```

_Note:_ This flag is necessary when attempting to scan images from the docker/podman daemon with different architectures than the host that is running TMAS.

**Overriding vulnerability and secret findings**:

```sh
tmas scan <artifact_to_scan> -VMS --override path/to/tmas_overrides.yml
```

Use the above command to override false positives or other vulnerability or secret findings you want to ignore. The override file uses a YAML structure with rules defined under each scan type, like `vulnerabilities` or `secrets` for example. When providing overrides for both secrets and vulnerabilities, specify all the overrides in the same YAML file. For more information, see [Override vulnerability and secret findings](#override-vulnerability-and-secret-findings).

Overriding malware findings is not supported at this time.

**Using the evaluatePolicy flag to evaluate scan results against the Vision One Code Security policy**:

```sh
tmas scan <artifact_to_scan> -VMS --evaluatePolicy
```

Use the above command to evaluate the scan results against your organization's Vision One Code Security policy. For more information, see [Evaluate scan results against the Vision One Code Security policy](#evaluate-scan-results-against-the-vision-one-code-security-policy).

**Using the distro flag to specify Operating System (OS) distribution details for open-source RPM file artifacts**:

The `--distro` vulnerabilities scanner flag lets you specify OS distribution details for file and directory artifacts which do not inherently contain OS information, such as open-source RPM files.
Specify the exact OS distribution where you plan to install the package to ensure accurate open-source vulnerability matching.

```sh
tmas scan file:sample-file.rpm -V --distro ol:8.4
```

The `--distro` flag is intended for scanning _unmodified_, open-source RPM files prior to their installation. This flag can only be used when scanning directory and file artifacts for vulnerabilities.
When scanning the root directory of a file-system (e.g., `tmas scan dir:/ -V`), TMAS automatically detects the OS distribution information based on the contents of the `/etc/os-release` file. Any value specified using the `--distro` flag will be ignored, and a warning message appears.

## Scan subcommands

```sh
tmas scan [subcommand] [artifact] [flags]
```

| Subcommand        | Description                                 |
| ----------------- | ------------------------------------------- |
| `vulnerabilities` | Perform a vulnerability scan on an artifact |
| `malware`         | Perform a malware scan on an image artifact |
| `secrets`         | Perform a secrets scan on an artifact.      |

### Vulnerabilities subcommand

```sh
tmas scan vulnerabilities <artifact_to_scan>
```

| Flag               | Description                                                                                                                                                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-p, --platform`   | Specify platform for multi-platform container image sources (optional).<br>For example: 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux' (default 'linux/amd64').                                                                                            |
| `-r, --region`     | Trend Vision One service regions: [ap-southeast-2 eu-central-1 ap-south-1 ap-northeast-1 ap-southeast-1 me-central-1 us-east-1], Trend Cloud One service regions: [au-1 ca-1 de-1 gb-1 in-1 jp-1 sg-1 us-1] (default is set to Vision One region "us-east-1") |
| `--saveSBOM`       | Save SBOM in the local directory (optional)                                                                                                                                                                                                                   |
| `--distro`         | Specify the distribution to match vulnerabilities against file and directory artifacts (optional).<br>Use the formation \<distro\>:\<version\>, like `ol:8.4`, for example.                                                                                   |
| `-o, --override`   | Specify the file path to the file containing the vulnerability override rules (optional).<br>For example: `/path/to/tmas_overrides.yml`.                                                                                                                      |
| `--evaluatePolicy` | Evaluate the scan results against the Vision One Code Security policy. TMAS will return the results and exit with status code '2' if the policy is violated.                                                                                                  |
| `-v, --verbose`    | Increase verbosity (-v = info, -vv = debug)                                                                                                                                                                                                                   |
| `-h, --help`       | Display help information.                                                                                                                                                                                                                                     |

Note the following:

- Vulnerability scans are limited to artifacts for which the generated SBOM data is less than 15 MB.

### Malware subcommand

```sh
tmas scan malware <artifact_to_scan>
```

| Flag               | Description                                                                                                                                                                                                                                                   |
| ------------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-p, --platform`   | Specify platform for multi-platform container image sources (optional).<br>For example: 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux' (default 'linux/amd64').                                                                                            |
| `-r, --region`     | Trend Vision One service regions: [ap-southeast-2 eu-central-1 ap-south-1 ap-northeast-1 ap-southeast-1 me-central-1 us-east-1], Trend Cloud One service regions: [au-1 ca-1 de-1 gb-1 in-1 jp-1 sg-1 us-1] (default is set to Vision One region "us-east-1") |
| `--evaluatePolicy` | Evaluate the scan results against the Vision One Code Security policy. TMAS will return the results and exit with status code '2' if the policy is violated.                                                                                                  |
| `-v, --verbose`    | Increase verbosity (-v = info, -vv = debug).                                                                                                                                                                                                                  |
| `-h, --help`       | Display help information.                                                                                                                                                                                                                                     |

Note the following:

- Malware scans only support `docker`, `docker-archive`, `oci-archive`, `oci-dir` and `registry` artifact types.
- The maximum single file size limit is 1 GB. The scan skips files larger than 1 GB.
- The maximum single layer size limit is 512 MB. The scan skips layers larger than 512 MB.

### Secrets subcommand

```sh
tmas scan secrets <artifact_to_scan>
```

| Flag               | Description                                                                                                                                                                                                                                                                                          |
| ------------------ | ---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `-p, --platform`   | Specify platform for multi-platform container image sources.<br/>For example, 'linux/arm64', 'linux/arm64/v8', 'arm64', 'linux'. The default is 'linux/amd64'.                                                                                                                                       |
| `-r, --region`     | Trend Vision One service regions: [ap-southeast-2 eu-central-1 ap-south-1 ap-northeast-1 ap-southeast-1 me-central-1 us-east-1], Trend Cloud One service regions: [au-1 ca-1 de-1 gb-1 in-1 jp-1 sg-1 us-1] (default is set to Vision One region "us-east-1")                                        |
| `-o, --override`   | Specify the file path to the file containing the secret override rules (optional).<br>For example: `/path/to/tmas_overrides.yml`.                                                                                                                                                                    |
| `--redacted`       | Redact secrets in the secrets finding report in the TMAS CLI output. This will remove sensitive information from the report, such as passwords, tokens, and other sensitive data. Secret findings are always redacted prior to being sent to Trend Micro's servers, regardless of this flag's state. |
| `--evaluatePolicy` | Evaluate the scan results against the Vision One Code Security policy. TMAS will return the results and exit with status code '2' if the policy is violated.                                                                                                                                         |
| `-v, --verbose`    | Increase verbosity (-v = info, -vv = debug).                                                                                                                                                                                                                                                         |
| `-h, --help`       | Display help information.                                                                                                                                                                                                                                                                            |

Note the following:

- Secret scans are limited to artifacts for which the generated secret findings report is less than 15 MB.
- Binary and zip files are not supported at this time.
- Secret scan findings are redacted prior to being sent to Trend Vision One for further processing.
- The secrets subcommand does not contribute results for the evaluation of Trend Cloud One Container Security admission control policies. Use the [Trend Micro Artifact Scanner in Trend Vision One](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-tmas-about) in order to include secret scan results in admission control evaluation.

## aiscan command usage

_Note:_ This feature is in [pre-release](https://docs.trendmicro.com/en-us/documentation/article/trend-vision-one-ai-scanner-ai-guard) and available only with Trend Vision One. If you are interested, please contact us to join!

```sh
tmas aiscan [subcommand] [flags]
```

| Subcommands | Description                              |
| ----------- | ---------------------------------------- |
| `llm`       | Scan an LLM endpoint for vulnerabilities |

_Note_: All `aiscan` subcommands require the `Run AI Scan` permission assigned to your Trend Vision One API KEY

### LLM subcommand

```sh
tmas aiscan llm [flags]
```

| Flag                | Description                                                                                                                               |
| ------------------- | ----------------------------------------------------------------------------------------------------------------------------------------- |
| `-i, --interactive` | Run a scan using the interactive form                                                                                                     |
| `-c, --config`      | Run a scan using the given config file                                                                                                    |
| `--output`          | Save scan results to file(s). Supports JSON and Markdown formats (e.g., `json=results.json,markdown=report.md`)                           |
| `-r, --region`      | Trend Vision One service regions: [ap-southeast-2 eu-central-1 ap-south-1 ap-northeast-1 ap-southeast-1 us-east-1] (default is us-east-1) |
| `-v, --verbose`     | Increase verbosity (-v = info, -vv = debug)                                                                                               |
| `-h, --help`        | Display help information                                                                                                                  |

Example Usage:

```sh
tmas aiscan llm -i
```

To perform a scan for a different region

```sh
tmas aiscan llm -i --region ap-south-1
```

After using the interactive mode to initiate a scan, you have the option to save the current scan config to a file. For subsequent scans, you can specify this file using the `--config` flag. When the --config flag you will also need to set the TARGET_API_KEY environment variable to your endpoint API KEY.

```bash
export TARGET_API_KEY=<your_api_key>
tmas aiscan llm -c config.yaml
```

To save scan results to files, use the `--output` flag:

```bash
# Save results as JSON
tmas aiscan llm -i --output json=ai-scan-results.json

# Save results as Markdown report
tmas aiscan llm -i --output markdown=ai-scan-report.md

# Save results in both formats
tmas aiscan llm -i --output json=results.json,markdown=report.md
```

## Proxy configuration

The CLI tool loads the proxy configuration from the following set of optional environment variables

| Environment Variable | Required or Optional | Description                                                                                                                                                                                                                       |
| -------------------- | -------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `NO_PROXY`           | Optional             | Add the Artifact Scanning as a Service and Malware Scanning as a Service endpoints to the comma-separated list of host names if you want to skip proxy settings for the CLI tool. Note: Only an asterisk, '\*' matches all hosts. |
| `HTTP_PROXY `        | Optional             | `http://proxy.example.com`                                                                                                                                                                                                        |
| `HTTPS_PROXY`        | Optional             | `https://proxy.example.com`<br><br> If the proxy server is a SOCKS5 proxy, you must specify the SOCKS5 protocol in the URL, as follows: `socks5://socks_proxy.example.com`.                                                       |
| `PROXY_USER`         | Optional             | Optional username for authentication header used in `Proxy-Authorization`.                                                                                                                                                        |
| `PROXY_PASS`         | Optional             | Optional password for authentication header used in `Proxy-Authorization`, used only when `PROXY_USER` is configured.                                                                                                             |

## Clean up temporary files

Each scan initiated against a registry image using the Trend Micro Artifact Scanner generates a new temporary directory under `$TMPDIR` to download and analyze the image.
For version 1.35.0 and later, this tool automatically removes those temporary files after scan execution.
To clean up existing temporary files that were generated with prior versions or by an interrupted scan, use the following commands (or its platform equivalent) under your discretion:

```sh
echo $TMPDIR
ls $TMPDIR | grep "stereoscope-"
cd $TMPDIR && rm -rf ./stereoscope-*
ls $TMPDIR | grep "stereoscope-"
```

## Override vulnerability and secret findings

If TMAS reports a vulnerability or secret which has been determined to be a false positive or any other finding you wish to ignore, you may instruct TMAS to override these findings by defining one or more rules in an override configuration file (for example, `~/tmas_overrides.yml`). Overriding malware findings is not supported at this time.

You can execute a scan using these rules by providing TMAS with a path to the override file using the `--override` flag.

```sh
tmas scan <artifact_to_scan> -VMS --override path/to/tmas_overrides.yml
```

The override file uses a YAML structure, with rules defined under each scan type, like `vulnerabilities` or `secrets` for example. When providing overrides for both secrets and vulnerabilities, specify all the overrides in the same YAML file.

### Override vulnerability findings

The vulnerability overrides are structured as a list of rules. Each rule can specify any combination of the following criteria:

- vulnerability ID (for example, `"CVE-2008-4318"`)
- fix state (allowed values: `"fixed"`, `"not-fixed"`, `"wont-fix"`, or `"unknown"`)
- package name (for example, `"libcurl"`)
- package version (for example, `"1.5.1"`)
- package type (for example, `"npm"`, `"go-package"`, `"rpm"`, or any package type appearing in the TMAS JSON vulnerability report)
- package location (for example, `"/usr/local/lib/node_modules/**"`; supports glob patterns)

Each rule must also be accompanied by a reason indicating why the rule was implemented (for example, false positive, mitigated, vulnerable package function is not called, and so on).

```yml
vulnerabilities:
  # This is the full set of supported rule fields:
  - rule:
      vulnerability: CVE-0000-0000
      fixState: unknown
      package:
        name: libcurl
        version: 1.5.1
        type: npm
        location: "/usr/local/lib/node_modules/**"
    reason: A descriptor specifying why the override rule implemented
```

A given vulnerability finding is overridden if any of the rules specified in the override file apply to the finding. A rule is considered to apply to a finding only if all the fields in the rule match those found in the vulnerability finding.

```yml
vulnerabilities:
  # Override vulnerability findings whose CVE-ID is CVE-0000-0000
  - rule:
      vulnerability: CVE-0000-0000
    reason: Not executed

  # Override vulnerability findings detected on libcurl version 1.5.1
  - rule:
      package:
        name: libcurl
        version: 1.5.1
    reason: Dev dependency
```

Any vulnerability finding that matches a rule is presented in the JSON report in an `"Overridden"` section, rather than classified under its severity.

```json
{
  "vulnerabilities": {
    "totalVulnCount": 1,
    "criticalCount": 0,
    "highCount": 0,
    "mediumCount": 0,
    "lowCount": 0,
    "negligibleCount": 0,
    "unknownCount": 0,
    "overriddenCount": 1,
    "findings": {
      "High": [],
      "Low": [],
      "Medium": [],
      "Negligible": [],
      "Overridden": [
        {
          "name": "libcurl",
          "type": "npm",
          "version": "1.5.1",
          "id": "CVE-0000-0000",
          "source": "https://nvd.nist.gov/vuln/detail/CVE-0000-0000",
          "severity": "Low",
          "fix": "not-fixed",
          "locations": ["/usr/local/lib/node_modules/**"],
          "cvssSummaries": [],
          "relatedVulnerabilities": []
        }
      ]
    }
  }
}
```

### Override secret findings

Secret overrides support multiple targets:

- paths
- rules
- findings

Each override is a list of regular expression patterns which should cause the target to be excluded. Each list of patterns must also be accompanied by a reason indicating why the rule was implemented (for example, "false positive", "third party dependencies", and so on).

```yml
secrets:
  paths:
    - patterns:
        - node_modules
        - .tox
      reason: Third party dependencies
    - patterns:
        - .*_test.go
      reason: Development resources
  rules:
    - patterns:
        - generic-api-key
      reason: A descriptor specifying why the override is implemented
  findings:
    - patterns:
        - ".*example"
      reason: "Used in testing"
```

A given secret finding is overridden if any of the regular expression specified in the override file apply to the finding.

Any secret finding that matches a rule is presented in the JSON report in an `"overridden"` section, rather than among the unmitigated findings.

```json
{
  "secrets": {
    "totalFilesScanned": 3,
    "unmitigatedFindingsCount": 0,
    "overriddenFindingsCount": 1,
    "findings": {
      "overridden": [
        {
          "ruleID": "aws-access-token",
          "description": "Identified a pattern that may indicate AWS credentials, risking unauthorized cloud resource access and data breaches on AWS platforms.",
          "secret": "AKIAIRYLJVKMPEXAMPLE",
          "location": {
            "path": "/workdir/test-fixtures/aws_access_key",
            "startLine": 1,
            "endLine": 1,
            "startColumn": 1,
            "endColumn": 20
          }
        }
      ]
    }
  }
}
```

## Evaluate scan results against the Vision One Code Security policy

When the `--evaluatePolicy` flag is set, TMAS will evaluate your scan results against your organization's Vision One Code Security policy. A default policy is provided for all accounts, or you can customize it in the Vision One console. If any blocking rules are violated by a security finding, TMAS will report the violations and exit with status code `2`.

Policy evaluation is available for the vulnerabilities, secrets, and malware scanners.

Usage examples:

```sh
tmas scan <artifact_to_scan> -VMS --evaluatePolicy
```

```sh
tmas scan vulnerabilities <artifact_to_scan> --evaluatePolicy
```

_Note:_ The `--evaluatePolicy` flag is a pre-release feature and is only supported with Trend Vision One accounts. In the next TMAS major release, policy evaluation will run automatically on vulnerabilities, secrets, and malware scans and this flag will be deprecated.
