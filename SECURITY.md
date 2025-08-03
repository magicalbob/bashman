# Security Policy for Bashman

## Supported Versions

We maintain security patches for the **1.x** line of Bashman. Releases older than this are unsupported and may contain vulnerabilities.

| Version  | Supported          |
| -------- | ------------------ |
| 1.x      | :white_check_mark: |
| < 1.0    | :x:                |

## Reporting a Vulnerability

Please report any security vulnerabilities or weaknesses by emailing our security team at **security@bashman.org**. We ask that you:

1. Provide a clear, concise description of the issue.  
2. Include steps to reproduce or a minimal proof-of-concept.  
3. Specify the version of Bashman you tested against and your environment (OS, shell).  
4. Avoid public disclosure until we have had a chance to investigate and address the issue.

## Security Response Process

1. **Acknowledgement**  
   We will respond within 48 hours to confirm receipt of your report.  
2. **Investigation**  
   We will assess the severity, reproduce the issue, and discuss mitigation.  
3. **Remediation**  
   A patch or workaround will be developed and tested.  
4. **Disclosure**  
   An advisory will be published (with credit, if desired) once a fix is available.  

## Patch Releases

We follow [Semantic Versioning](https://semver.org/). Security fixes will be released as:

- **Patch** version bumps for non-breaking fixes (e.g. `1.2.3` → `1.2.4`).  
- **Minor** version bumps only if the fix introduces new, non-breaking features.

## Upgrading

To upgrade to the latest patched version:

```bash
bashman update
```

## Acknowledgments
Thank you to everyone who helps us keep Bashman secure!

---

Feel free to adjust email addresses, supported versions, or response times to match your p
