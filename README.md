# graylog-contentpack-openldap
Graylog contentpack for Openldap
Based on the great work here: https://github.com/ltb-project/openldap-elk

# Presentation
This is based on [Processing Pipeline](http://docs.graylog.org/en/latest/pages/pipelines.html)
# Usage
Create a new

## Stage 0
-> Rule source:
```
rule "OpenLDAP extraction"
when
    has_field("message")
then
    let pattern = "(?:(?:<= (?:b|m)db_%{DATA:index_error_filter_type}_candidates: \\(%{WORD:index_error_attribute_name}\\) not indexed)|(?:ppolicy_%{DATA:ppolicy_op}: %{DATA:ppolicy_data})|(?:connection_input: conn=%{INT:connection} deferring operation: %{DATA:deferring_op})|(?:connection_read\\(%{INT:fd_number}\\): no connection!)|(?:conn=%{INT:connection} (?:(?:fd=%{INT:fd_number} (?:(?:closed(?: \\(connection lost\\)|))|(?:ACCEPT from IP=%{IP:src_ip}\\:%{INT:src_port} \\(IP=%{IP:dst_ip}\\:%{INT:dst_port}\\))|(?:TLS established tls_ssf=%{INT:tls_ssf} ssf=%{INT:ssf})))|(?:op=%{INT:operation_number} (?:(?:(?:(?:SEARCH )|(?:))RESULT (?:tag=%{INT:tag}|oid=(?:%{DATA:oid}(?:))) err=%{INT:error_code}(?:(?: nentries=%{INT:nentries})|(?:)) text=(?:(?:%{DATA:error_text})|(?:)))|(?:%{WORD:operation_name}(?:(?: %{DATA:data})|(?:))))))))%{SPACE}$";
    let message_text = to_string($message.message);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
end
```

## Stage 1
Rule: OpenLDAP extraction BIND
```
rule "OpenLDAP extraction BIND"
when
    has_field("operation_name") && $message.operation_name=="BIND"
then
    let pattern = "(?:(?:(?<bind_dn>anonymous))|(?:dn=\"%{DATA:bind_dn}\")) (?:(?:method=%{WORD:bind_method})|(?:mech=%{WORD:bind_mech} ssf=%{INT:bind_ssf}))%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```

Rule: OpenLDAP extraction SRCH
```
rule "OpenLDAP extraction SRCH"
when
    has_field("operation_name") && $message.operation_name=="SRCH"
then
    let pattern = "(?:(?:base=\"%{DATA:search_base}\" scope=%{INT:search_scope} deref=%{INT:search_deref} filter=\"%{DATA:search_filter}\")|(?:attr=%{DATA:search_attr}))%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```

Rule: OpenLDAP extraction MOD
```
rule "OpenLDAP extraction MOD"
when
    has_field("operation_name") && $message.operation_name=="MOD"
then
    let pattern = "(?:(?:dn=\"%{DATA:mod_dn}\")|(?:attr=%{DATA:mod_attr}))%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```

Rule: OpenLDAP extraction ADD
```
rule "OpenLDAP extraction ADD"
when
    has_field("operation_name") && $message.operation_name=="ADD"
then
    let pattern = "dn=\"%{DATA:add_dn}\"%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```

Rule: OpenLDAP extraction MODRDN
```
rule "OpenLDAP extraction MODRDN"
when
    has_field("operation_name") && $message.operation_name=="MODRDN"
then
    let pattern = "dn=\"%{DATA:modrdn_dn}\"%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```

Rule: OpenLDAP extraction DEL
```
rule "OpenLDAP extraction DEL"
when
    has_field("operation_name") && $message.operation_name=="DEL"
then
    let pattern = "dn=\"%{DATA:del_dn}\"%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```

Rule: OpenLDAP extraction CMP
```
rule "OpenLDAP extraction CMP"
when
    has_field("operation_name") && $message.operation_name=="CMP"
then
    let pattern = "dn=\"%{DATA:cmp_dn}\" attr=\"%{DATA:cmp_attr}\"%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```
Rule: OpenLDAP extraction EXT
```
rule "OpenLDAP extraction EXT"
when
    has_field("operation_name") && $message.operation_name=="EXT"
then
    let pattern = "oid=%{DATA:ext_oid}%{SPACE}$";
    let message_text = to_string($message.data);
    let matches = grok(pattern: pattern, value: message_text);
    set_fields(matches);
    remove_field("data");
end
```
