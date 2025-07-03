#!/bin/bash

# --- Script de Implantação Automatizada de Regras e Respostas Ativas Refinadas ---
# --- Foco: Detecção de Alta Confiança e Bloqueio de Ameaças FileLess ---

# --- Conteúdo das Regras Refinadas ---
RULES_XML='
<group name="custom_rules,fileless_detection,">

  <rule id="100010" level="12" overwrite="yes">
    <if_sid>60137</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(invoke-expression|iex).*(downloadstring|downloadfile)</field>
    <description>Ameaça Fileless de Alta Confiança: PowerShell executando script baixado da web em memória (IEX/DownloadString).</description>
    <mitre><id>T1059.001</id></mitre>
  </rule>

  <rule id="100013" level="10">
    <if_sid>60137</if_sid>
    <field name="win.eventdata.scriptBlockText" type="pcre2">(?i)(-encodedcommand|-enc)\s+[a-zA-Z0-9+/=]{512,}</field>
    <description>Ameaça Fileless Potencial: PowerShell executado com um comando codificado muito longo.</description>
    <mitre><id>T1027</id></mitre>
  </rule>

  <rule id="100011" level="12" overwrite="yes">
    <if_sid>60108</if_sid>
    <field name="win.eventdata.command" type="pcre2">(?i)(powershell|cmd).*( -enc|encodedcommand|-w hidden|iex|invoke-expression|downloadstring)</field>
    <description>Ameaça Fileless de Alta Confiança: Tarefa agendada criada com parâmetros suspeitos.</description>
    <mitre><id>T1053.005</id></mitre>
  </rule>
  
  <rule id="100012" level="13" overwrite="yes">
    <if_sid>61600</if_sid>
    <field name="win.eventdata.eventID">8</field>
    <field name="win.eventdata.targetImage" type="pcre2">(?i)lsass.exe|explorer.exe|svchost.exe|winlogon.exe</field>
    <field name="win.eventdata.sourceImage" negate="yes">C:\\Program Files\\FerramentaDeSeguranca\\agent.exe</field>
    <field name="win.eventdata.sourceImage" negate="yes">C:\\Program Files\\SoftwareDeMonitoramento\\monitor.exe</field>
    <description>Ameaça Fileless Avançada: Injeção de Thread Remota em Processo Crítico (Sysmon ID 8).</description>
    <mitre><id>T1055.002</id></mitre>
  </rule>

</group>
'

# --- Conteúdo da Resposta Ativa para as Regras Refinadas ---
AR_XML='
  <command>
    <name>win_disable-account</name>
    <executable>disable-account.cmd</executable>
    <extra_args>-u ${win.eventdata.subjectUserName}</extra_args>
    <timeout_allowed>no</timeout_allowed>
  </command>
  <command>
    <name>win_isolate-host</name>
    <executable>route-null.cmd</executable>
    <timeout_allowed>yes</timeout_allowed>
  </command>
  
  <active-response>
    <description>Desabilita conta de usuário após execução de PowerShell suspeito</description>
    <rules_id>100010, 100013</rules_id>
    <command>win_disable-account</command>
    <location>local</location>
  </active-response>

  <active-response>
    <description>Desabilita conta de usuário após criação de tarefa agendada suspeita</description>
    <rules_id>100011</rules_id>
    <command>win_disable-account</command>
    <location>local</location>
  </active-response>
  
  <active-response>
    <description>Isola o host da rede após detecção de injeção de thread</description>
    <rules_id>100012</rules_id>
    <command>win_isolate-host</command>
    <location>local</location>
    <timeout>600</timeout>
  </active-response>
'

echo "Iniciando configuração de segurança avançada..."

# Adiciona as regras refinadas ao final do arquivo local_rules.xml
echo "$RULES_XML" >> /var/ossec/etc/rules/local_rules.xml

# Adiciona a resposta ativa dentro do ossec.conf
# Este comando insere o conteúdo de AR_XML antes da última linha (</ossec_config>)
sed -i -e "/<\/ossec_config>/i $AR_XML" /var/ossec/etc/ossec.conf

# Reinicia o serviço
echo "Reiniciando o Wazuh Manager para aplicar as novas configurações..."
systemctl restart wazuh-manager

echo "Processo finalizado."
echo "Verifique o status do serviço com: systemctl status wazuh-manager"
