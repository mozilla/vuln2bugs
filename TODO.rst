TODO
====

- Refactor the VulnProcessor (currently its just getting everything out of one function).
- Support custom SLAs (currently it's hardcoded to 7 days).
- Support true-services (MozDef index currently does not expose them).
- Support AssetCore (MozDef currently does not have this functionality implemented).
- Reimplement as a MozDef alert plugin for Bugzilla (need Kibana 4 support so that dashboards can be dynamically linked,
  instead of processing the filters in the script)
