# Wazuh Ruleset
---
### Índice

1. Reglas y decoders custom

El ruleset de Wazuh se utiliza por el sistema para detectar ataques, intrusiones, usos incorrectos de software, problemas de configuración, errores en aplicxaciones, malware, rootkits, anomalías en el sistema o violaciones de las políticas de seguridad.

Los desarrolladores de wazuh tienen un [repo](https://github.com/wazuh/wazuh/tree/4.2/ruleset) en el que centralizan, prueban y mantienen los decoders y reglas que suben contribuidores open source. También suben nuevas reglas o rootchecks para que los use la comunidad.

### Reglas y decoders custom

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
