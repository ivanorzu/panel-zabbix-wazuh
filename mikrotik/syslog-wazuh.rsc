# RouterOS 7.x -> Wazuh por syslog.  Probado en RouterOS 7.18.
# Ajustar: IP de Wazuh, nombres de interfaz publica y log-prefix.
# Cargar con:  /import file-name=syslog-wazuh.rsc   (o pegar por partes en el terminal)

# 1) Accion de log remota. En 7.18 remote-log-format solo acepta default|syslog|cef:
#    se deja el formato por defecto, que es el que entienden los decoders de este repo.
/system logging action add name=wazuh target=remote remote=192.168.10.57 remote-port=514

# 2) Temas que se envian
/system logging add action=wazuh topics=critical
/system logging add action=wazuh topics=error
/system logging add action=wazuh topics=warning
/system logging add action=wazuh topics=account
/system logging add action=wazuh topics=firewall

# 3) Registrar SOLO los TCP SYN nuevos que llegan por cada interfaz publica.
#    - tcp-flags=syn,!ack  : solo intentos de conexion (UDP/ICMP generan ruido: respuestas
#                            QUIC o STUN se ven como "nuevas" y agotan el limite)
#    - limit=2,10:packet   : tope de frecuencia para no inundar el log ni a Wazuh
#    - place-before=0      : la regla de log va ANTES de las que descartan; si no, no se ve nada
/ip firewall filter add chain=input action=log connection-state=new protocol=tcp \
    tcp-flags=syn,!ack in-interface=sfp28-2  limit=2,10:packet log-prefix=WANIN-ISP1 \
    comment="log intentos desde internet (ISP1)" place-before=0
/ip firewall filter add chain=input action=log connection-state=new protocol=tcp \
    tcp-flags=syn,!ack in-interface=sfp28-10 limit=2,10:packet log-prefix=WANIN-ISP2 \
    comment="log intentos desde internet (ISP2)" place-before=0

# 4) Comprobar que sale algo (el mensaje debe aparecer en archives.log de Wazuh si logall=yes
#    TEMPORALMENTE, o con tcpdump -ni any udp port 514 en el servidor Wazuh)
#   /log warning "prueba-wazuh"      <- genera una linea de prueba que debe llegar a Wazuh

# PENDIENTE DE DECISION (no se hace automaticamente): un descarte final en la cadena input para
# las interfaces publicas, una vez observados unos dias los intentos que llegan.
#   /ip firewall filter add chain=input in-interface=sfp28-2  action=drop comment="drop final ISP1"
