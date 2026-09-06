# Curveball response — Graph-identified privacy-boundary code paths

Requirement 6 of the privacy Curveball: *use Entire Graph to identify every code path
affected by this privacy boundary.* Every query below is reproducible.

Commit: `1fbe30f8ae7112148c1ee355cd999b72ed573d46`

## `BuildExport`
```
$ entire graph neighbors --repo . --symbol BuildExport --relation CALLS --direction in --format json
  CALLED BY:
    (none)
  CALLS:
    (none)
```

## `sanitizeSummary`
```
$ entire graph neighbors --repo . --symbol sanitizeSummary --relation CALLS --direction in --format json
  CALLED BY:
    (none)
  CALLS:
    (none)
```

## `MarshalExport`
```
$ entire graph neighbors --repo . --symbol MarshalExport --relation CALLS --direction in --format json
  CALLED BY:
    (none)
  CALLS:
