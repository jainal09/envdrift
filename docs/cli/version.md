# envdrift version

Show the installed envdrift version.

## Synopsis

```bash
envdrift version
```

## Description

Displays the current version of envdrift installed in your environment.

## Examples

```bash
envdrift version
```

Output:

```text
envdrift 0.1.0
```

## Use Cases

### Check Installed Version

```bash
envdrift version
```

### Verify Installation

```bash
# After installing
pip install envdrift
envdrift version
```

### CI/CD Debugging

```yaml
# GitHub Actions
- name: Check envdrift version
  run: envdrift version
```

### Compare Versions

```bash
# Check if you have the latest
pip index versions envdrift
envdrift version
```

## See Also

- [Installation](../getting-started/installation.md) - How to install envdrift
