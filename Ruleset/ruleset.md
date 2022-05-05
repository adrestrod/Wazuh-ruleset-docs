# Wazuh Ruleset
---
### Índice

1. Reglas y decoders custom

El ruleset de Wazuh se utiliza por el sistema para detectar ataques, intrusiones, usos incorrectos de software, problemas de configuración, errores en aplicxaciones, malware, rootkits, anomalías en el sistema o violaciones de las políticas de seguridad.

Los desarrolladores de wazuh tienen un [repo](https://github.com/wazuh/wazuh/tree/4.2/ruleset) en el que centralizan, prueban y mantienen los decoders y reglas que suben contribuidores open source. También suben nuevas reglas o rootchecks para que los use la comunidad.

### Reglas y decoders custom

#### Añadir Nuevas reglas y decoders

Es posible modificar las reglas y decoders que trae wazuh por defecto para adaptarlas a las necesidades de cada red o empresa.

Para explicar como funcionan estas personalizaciones voy a tomar los mismos ejemplos que Wazuh da en su documentación.

Dado este log de un programa ejemplo:
```log
 Dec 25 20:45:02 MyHost example[12345]: User 'admin' logged from '192.168.1.100'
```

Primero tenemos que crear un decoder para decodificar la información recibida, en la ruta `/var/ossec/etc/decoders/local_decoder.xml`

```xml
<decoder name="example">
  <program_name>^example</program_name>
</decoder>

<decoder name="example">
  <parent>example</parent>
  <regex>User '(\w+)' logged from '(\d+.\d+.\d+.\d+)'</regex>
  <order>user, srcip</order>
</decoder>
```

Este decoder lo que hace es leer el programa con `<program_name>`. Una vez detecta que el log viene del pregrama especifiicado (es este caso `example`) se ejecuta la segunda parte del decoder que lo que va a hacer es, usando Regex formatea el log para dejar los datos qeu se pasan por regex en las variables especificadas en el `order`.


Y ahora añadimos la siguiente regla a `/var/ossec/etc/rules/local_rules.xml`

```xml
<rule id="100010" level="0">
  <program_name>example</program_name>
  <description>User logged</description>
</rule>
```



Y para probar que funciona, podemos utilizar el comando `/var/ossec/bin/wazuh-logtest`

```bash
Type one log per line

Dec 25 20:45:02 MyHost example[12345]: User 'admin' logged from '192.168.1.100'

**Phase 1: Completed pre-decoding.
        full event: 'Dec 25 20:45:02 MyHost example[12345]: User 'admin' logged from '192.168.1.100''
        timestamp: 'Dec 25 20:45:02'
        hostname: 'MyHost'
        program_name: 'example'

**Phase 2: Completed decoding.
        name: 'example'
        dstuser: 'admin'
        srcip: '192.168.1.100'

**Phase 3: Completed filtering (rules).
        id: '100010'
        level: '0'
        description: 'User logged'
        groups: '['local', 'syslog', 'sshd']'
        firedtimes: '1'
        mail: 'False'
```



Si queremos modificar una regla, debemos encontrar la regla que queremos modificar, por ejemplo, la regla de ssh. 

Se encuentra en ` /var/ossec/ruleset/rules/0095-sshd_rules.xml `

Copiamos la regla que queramos modificar y la pegamos en ` /var/ossec/etc/rules/local_rules.xml `, modificando lo que necesitemos añadiendole el ` overwrite="yes" ` para indicarle a Wazuh que esta regla sobreescribe a una ya existente.

* regla original

```xml
<rule id="5710" level="5">
  <if_sid>5700</if_sid>
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>invalid_login,authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,gpg13_7.1,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
</rule>
```

* regla modificada
```xml
<rule id="5710" level="10" overwrite="yes">
  <if_sid>5700</if_sid>
  <match>illegal user|invalid user</match>
  <description>sshd: Attempt to login using a non-existent user</description>
  <mitre>
    <id>T1110</id>
  </mitre>
  <group>invalid_login,authentication_failed,pci_dss_10.2.4,pci_dss_10.2.5,pci_dss_10.6.1,gpg13_7.1,gdpr_IV_35.7.d,gdpr_IV_32.2,hipaa_164.312.b,nist_800_53_AU.14,nist_800_53_AC.7,nist_800_53_AU.6,tsc_CC6.1,tsc_CC6.8,tsc_CC7.2,tsc_CC7.3,</group>
</rule>
```

#### Cambiar un decoder existente

Para modificar un decoder, no se puede hacer como con las reglas. Dememos seguir el siguiente procedimiento:

1. Copiamos el archivo de la carpeta por defecto de Wazuh ` /var/ossec/ruleset/decoders/0310-ssh_decoders.xml `  para realizar los cambios en otra carpeta, en este caso ` /var/ossec/etc/decoders `. 

2. Excluímos ese archivo de la lista de carga. Para esto usamos la etiqueta ` <decoder-exclude> ` en el archivo ` ossec.conf `. Una vez ,odifiquemos este archivo de configuración, Wazuh cargará el archivo que nosotros hemos copiado en lugar del original. 

```xml
<ruleset>
  <!-- Default ruleset -->
  <decoder_dir>ruleset/decoders</decoder_dir>
  <rule_dir>ruleset/rules</rule_dir>
  <rule_exclude>0215-policy_rules.xml</rule_exclude>
  <list>etc/lists/audit-keys</list>

  <!-- User-defined ruleset -->
  <decoder_dir>etc/decoders</decoder_dir>
  <rule_dir>etc/rules</rule_dir>
  <decoder_exclude>ruleset/decoders/0310-ssh_decoders.xml</decoder_exclude>
</ruleset>
```

3. Hacemos los cambios en el archivo ` /var/ossec/ruleset/decoders/0310-ssh_decoders.xml `

### Campos dinámicos

#### Decoders tradicionales

Originalmente Wauh solo permitia utilizar 13 campos predefinidos para guardar la infomarción extraída por los decoders (_user, srcip, dstip, srcport, dstport, protocol, action, id, url, data, extra\_data, status, system\_name_), de los que solo ocho se podían usar simultáneamente.

Ejemplo de la forma antigua:

```xml
<decoder name="web-accesslog">
  <type>web-log</type>
  <prematch>^\d+.\d+.\d+.\d+ - </prematch>
  <regex>^(\d+.\d+.\d+.\d+) - \S+ [\S+ -\d+] </regex>
  <regex>"\w+ (\S+) HTTP\S+ (\d+) </regex>
  <order>srcip,url,id</order>
</decoder>
```
#### Decoders dinámicos

A veces, es necesario extraer información mas específica de los logs recibidos para poder tratarlos mejor. Por eso ahroa es posible extraer un número ilimitado de campos y nombrarlos de la forma que nosotros necesitemos en cada momento. Tambien soporta nombres anidados.

```xml
<decoder name="auditd-config_change">
  <parent>auditd</parent>
  <regex offset="after_regex">^auid=(\S+) ses=(\S+) op="(\.+)"</regex>
  <order>audit.auid,audit.session,audit.op</order>
</decoder>
```
Wazuh transforma lo que haya dentro de `order` en un campo JSON 

En el siguiente ejemplo se ve exactamente como el decoder extrae la información de una alerta:


```bash
** Alert 1486483073.60589: - audit,audit_configuration,
2017 Feb 07 15:57:53 wazuh-example->/var/log/audit/audit.log
Rule: 80705 (level 3) -> 'Auditd: Configuration changed'
type=CONFIG_CHANGE msg=audit(1486483072.194:20): auid=0 ses=6 op="add rule" key="audit-wazuh-a" list=4 res=1
audit.type: CONFIG_CHANGE
audit.id: 20
audit.auid: 0
audit.session: 6
audit.op: add rule
audit.key: audit
audit.list: 4
audit.res: 1
```
Salida JSON:

```json
{
  "rule": {
    "level": 3,
    "description": "Auditd: Configuration changed",
    "id": 80705,
    "firedtimes": 2,
    "groups": [
      "audit",
      "audit_configuration"
    ]
  },
  "agent": {
    "id": "000",
    "name": "wazuh-example"
  },
  "manager": {
    "name": "wazuh-example"
  },
  "full_log": "type=CONFIG_CHANGE msg=audit(1486483072.194:20): auid=0 ses=6 op=\"add rule\" key=\"audit-wazuh-a\" list=4 res=1",
  "audit": {
    "type": "CONFIG_CHANGE",
    "id": "20",
    "auid": "0",
    "session": "6",
    "op": "add rule",
    "key": "audit",
    "list": "4",
    "res": "1"
  },
  "decoder": {
    "parent": "auditd",
    "name": "auditd"
  },
  "timestamp": "2017 Feb 07 15:57:53",
  "location": "/var/log/audit/audit.log"
}
```


### Sintáxis

Debido a que en este documento nos centramos en las reglas de Wazuh, vamos a centrarnos en la sintáxis específica de estas .

#### Visión general

The **xml labels** used to configure ` rules ` are listed here.

| Option                | Values                                            | Description                                                                                                                          |
|-----------------------|---------------------------------------------------|--------------------------------------------------------------------------------------------------------------------------------------|
| rule                  | See table below.                                  | Its starts a new rule and its defining options.                                                                                      |
| match                 | Any regular expression.                           | It will attempt to find a match in the log using sregex  by
default, deciding if the rule should be triggered.                       |
| regex                 | Any regular expression.                           | It does the same as match, but with regex as default.                                                                                |
| decoded_as            | Any decoder’s name.                               | It will match with logs that have been decoded by a specific decoder.                                                                |
| category              | Any type.                                         | It will match with logs whose decoder’s type concur.                                                                                 |
| field                 | Name and any regular expression.                  | It will compare a field extracted by the decoder in order with a
regular expression.                                                 |
| srcip                 | Any IP address.                                   | It will compare the IP address with the IP decoded as srcip. Use “!” to negate it.                                                   |
| dstip                 | Any IP address.                                   | It will compare the IP address with the IP decoded as dstip. Use “!” to negate it.                                                   |
| srcport               | Any regular expression.                           | It will compare a regular expression representing a port with a value decoded as srcport.                                            |
| dstport               | Any regular expression.                           | It will compare a regular expression representing a port with a value decoded as dstport.                                            |
| data                  | Any regular expression.                           | It will compare a regular expression representing a data with a value decoded as  data.                                              |
| extra_data            | Any regular expression.                           | It will compare a regular expression representing a extra data with a value decoded
as extra_data.                                   |
| user                  | Any regular expression.                           | It will compare a regular expression representing a user with a value decoded as user.                                               |
| system_name           | Any regular expression.                           | It will compare a regular expression representing a system name with a value decoded
as system_name.                                 |
| program_name          | Any regular expression.                           | It will compare a regular expression representing a program name with a value pre-decoded
as program_name.                           |
| protocol              | Any regular expression.                           | It will compare a regular expression representing a protocol with a value decoded as protocol.                                       |
| hostname              | Any regular expression.                           | It will compare a regular expression representing a hostname with a value pre-decoded
as hostname.                                   |
| time                  | Any time range. e.g. (hh:mm-hh:mm)                | It checks if the event was generated during that time range.                                                                         |
| weekday               | monday - sunday, weekdays, weekends               | It checks whether the event was generated during certain weekdays.                                                                   |
| id                    | Any regular expression.                           | It will compare a regular expression representing an ID with a value decoded as id                                                   |
| url                   | Any regular expression.                           | It will compare a regular expression representing a URL with a value decoded as url                                                  |
| location              | Any regular expression.                           | It will compare a regular expression representing a location with a value pre-decoded
as location.                                   |
| action                | Any String or regular expression.                 | It will compare a string or regular expression representing an action with a value decoded
as action.                                |
| status                | Any regular expression.                           | It will compare a regular expression representing a status with a value decoded as status.                                           |
| srcgeoip              | Any regular expression.                           | It will compare a regular expression representing a GeoIP source with a value decoded
as srcgeoip.                                   |
| dstgeoip              | Any regular expression.                           | It will compare a regular expression representing a GeoIP destination with a value decoded
as dstgeoip.                              |
| if_sid                | A list of rule IDs separated by commas or spaces. | It works similar to parent decoder. It will match when a rule ID on the list has previously matched.                                 |
| if_group              | Any group name.                                   | It will match if the indicated group has matched before.                                                                             |
| if_level              | Any level from 1 to 16.                           | It will match if that level has already been triggered by another rule.                                                              |
| if_matched_sid        | Any rule ID (Number).                             | Similar to if_sid but it will only match if the ID has been triggered in a period of time.                                           |
| if_matched_group      | Any group name.                                   | Similar to if_group but it will only match if the group has been triggered in a period of time.                                      |
| same_id               | None.                                             | The decoded id must be the same.                                                                                                     |
| different_id          | None.                                             | The decoded id must be different.                                                                                                    |
| same_srcip            | None.                                             | The decoded srcip must be the same.                                                                                                  |
| different_srcip       | None.                                             | The decoded srcip must be different.                                                                                                 |
| same_dstip            | None.                                             | The decoded dstip must be the same.                                                                                                  |
| different_dstip       | None.                                             | The decoded dstip must be different.                                                                                                 |
| same_srcport          | None.                                             | The decoded srcport must be the same.                                                                                                |
| different_srcport     | None.                                             | The decoded srcport must be different.                                                                                               |
| same_dstport          | None.                                             | The decoded dstport must be the same.                                                                                                |
| different_dstport     | None.                                             | The decoded dstport must be different.                                                                                               |
| same_location         | None.                                             | The location must be the same.                                                                                                       |
| different_location    | None.                                             | The location must be different.                                                                                                      |
| same_srcuser          | None.                                             | The decoded srcuser must be the same.                                                                                                |
| different_srcuser     | None.                                             | The decoded srcuser must be different.                                                                                               |
| same_user             | None.                                             | The decoded user must be the same.                                                                                                   |
| different_user        | None.                                             | The decoded user must be different.                                                                                                  |
| not_same_agent        | None.                                             | The decoded agent must be different.                                                                                                 |
| same_field            | None.                                             | The decoded field must be the same as the previous ones.                                                                             |
| different_field       | None.                                             | The decoded field must be different than the previous ones.                                                                          |
| same_protocol         | None.                                             | The decoded protocol must be the same.                                                                                               |
| different_protocol    | None.                                             | The decoded protocol must be different.                                                                                              |
| same_action           | None.                                             | The decoded action must be the same.                                                                                                 |
| different_action      | None.                                             | The decoded action must be different.                                                                                                |
| same_data             | None.                                             | The decoded data must be the same.                                                                                                   |
| different_data        | None.                                             | The decoded data must be different.                                                                                                  |
| same_extra_data       | None.                                             | The decoded extra_data must be the same.                                                                                             |
| different_extra_data  | None.                                             | The decoded extra_data must be different.                                                                                            |
| same_status           | None.                                             | The decoded status must be the same.                                                                                                 |
| different_status      | None.                                             | The decoded status must be different.                                                                                                |
| same_system_name      | None.                                             | The decoded system_name must be the same.                                                                                            |
| different_system_name | None.                                             | The decoded system_name must be different.                                                                                           |
| same_url              | None.                                             | The decoded url must be the same.                                                                                                    |
| different_url         | None.                                             | The decoded url must be different.                                                                                                   |
| same_srcgeoip         | None.                                             | The decoded srcgeoip must the same.                                                                                                  |
| different_srcgeoip    | None.                                             | The decoded srcgeoip must be different.                                                                                              |
| same_dstgeoip         | None.                                             | The decoded dstgeoip must the same.                                                                                                  |
| different_dstgeoip    | None.                                             | The decoded dstgeoip must be different.                                                                                              |
| description           | Any String.                                       | Provides a human-readable description to explain what is the purpose of the rule. Please, use this
field when creating custom rules. |
| list                  | Path to the CDB file.                             | Perform a CDB lookup using an ossec list.                                                                                            |
| info                  | Any String.                                       | Extra information using certain attributes.                                                                                          |
| options               | See the table below.                              | Additional rule options that can be used.                                                                                            |
| check_diff            | None.                                             | Determines when the output of a command changes.                                                                                     |
| group                 | Any String.                                       | Add additional groups to the alert.                                                                                                  |
| mitre                 | See Mitre table below.                            | Contains Mitre Technique IDs that fit the rule                                                                                       |
| var                   | Name for the variable. Most used: BAD_WORDS       | Defines a variable that can be used anywhere inside the same file.                                                                   |



Para mas detalle en que hace cada uno de estos parámetros con ejemlos se pueden encontrar [aquí](https://documentation.wazuh.com/current/user-manual/ruleset/ruleset-xml-syntax/rules.html)

