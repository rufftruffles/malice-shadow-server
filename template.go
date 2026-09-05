package main

const tpl = `#### ShadowServer
{{ if .WhiteList }}
##### WhiteList
| Filename      | Description      | ProductName      |
|:-------------:|:----------------:|:----------------:|
| {{index .WhiteList "filename"}} | {{index .WhiteList "description"}} | {{index .WhiteList "product_name"}} |
{{- else if .SandBox.Antivirus -}}
##### AntiVirus
 - FirstSeen: {{index .SandBox.MetaData "first_seen"}}
 - LastSeen: {{index .SandBox.MetaData "last_seen"}}

| Vendor          | Signature        |
|:----------------|:-----------------|
{{- range $key, $value := .SandBox.Antivirus }}
| {{ $key }} | {{ $value }} |
{{- end }}
{{- else if .SandBox.Error -}}
 - Sandbox: {{.SandBox.Error}}
{{- else if .Error -}}
 - Lookup: {{.Error}}
{{- else }}
 - Not found
{{- end }}
`
