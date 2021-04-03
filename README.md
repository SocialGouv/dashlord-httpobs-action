# httpobs-action

Run Mozilla HTTP Observatory scan and report results as JSON.

## Usage

```yaml
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: "socialgouv/httpobs-action@master"
        with:
          url: http://www.free.fr
          output: report.json
```
