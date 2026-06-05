# Guía de Análisis — PCAP `minergia_ot_mayo2026.pcap`

**Caso:** Minergia Atacama S.A. · **Curso:** Ciberseguridad Industrial · **Docente:** Sebastián Vargas Yáñez

Captura sintética (didáctica) del tráfico de la red OT durante mayo de 2026. Contiene tráfico de proceso normal
(línea base) y los artefactos de la campaña de intrusión descrita en la Parte 2 del caso. Abrible en **Wireshark**,
**tshark** y **Zeek**. ~10.500 paquetes · ~800 KB · **353 IPs únicas** · rango 01–31 may 2026 (UTC).

> Todos los datos son ficticios y fueron generados para el ejercicio. No corresponden a tráfico real.

---

## Inventario de equipos vivos (con tráfico) — coherente con el caso

| Tipo | Cantidad | Segmento (ejemplo) |
|---|---|---|
| PLC / RTU | 120 | El Roble `10.50.1.21–97` · Atacama `10.60.1.20–62` |
| IED / protección | 50 | `10.60.2.x` · `10.50.4.x` (IEC-104 / 2404) |
| HMI | 45 | `10.50.3.x` · `10.60.3.x` |
| IIoT / sensores | 80 | `10.50.2.x` · `10.60.4.x` (telemetría UDP/8883) |
| Estaciones IT corp. | 34 | `10.20.3.x` |
| Servidores | 15 | `10.20.1.60–74` |
| SCADA / DCS | 2 | `10.50.1.10` (Wonderware) · `10.60.1.10` (ABB) |
| Historiador PI | 2 | `10.40.1.20` · réplica DMZ `10.40.1.21` |
| Infra (DNS/NTP/colector) | 3 | `10.10.0.x` · `10.40.2.9` |
| DMZ jump | 1 | `10.30.1.5` |
| **Total equipos vivos** | **~356** | (≈300 que un NDR descubriría por red) |

> Esto reproduce a escala de red el inventario del caso (120 PLC/RTU, 50 IED, 376 IIoT, etc.). En el PCAP se
> incluye un subconjunto representativo de IIoT para mantener el archivo liviano; el ejercicio de inventario
> debe arrojar **≳300 activos**, evidenciando la brecha de visibilidad descrita en el informe.

## Hosts clave del ataque

| Host | IP | Rol |
|---|---|---|
| Estación de ingeniería | `10.20.4.66` | **Pivote comprometido** |
| PLC dosificación | `10.50.1.34` | **Objetivo de escritura no autorizada (E-07)** |
| PLC flotación | `10.50.1.21` | Objetivo de enumeración |
| Siemens S7-1500 | `10.50.1.50` | **Objetivo del STOP CPU (E-08)** |
| Historiador PI | `10.40.1.20` | **Origen de exfiltración (E-09)** |
| Jump server DMZ | `10.30.1.5` | Punto de entrada lateral |
| DNS interno | `10.10.0.53` | Resolución (abusada en C2) |
| VPN proveedor (externo) | `185.220.101.44` | **Acceso inicial (E-04)** |
| C2 | `45.137.21.190` | Comando y control |

---

## Filtros de Wireshark por evento

| Evento | Descripción | Filtro Wireshark |
|---|---|---|
| Línea base | Polling Modbus normal (FC03) | `modbus && mbtcp.modbus.func_code == 3` |
| **E-01** | Port scan corp→OT (SYN a 502/102/44818) | `tcp.flags.syn==1 && tcp.flags.ack==0 && (tcp.dstport==502 || tcp.dstport==102 || tcp.dstport==44818)` |
| **E-02** | Enumeración Modbus *Read Device ID* | `mbtcp && modbus.func_code == 43` |
| **E-04** | Acceso VPN proveedor sin MFA | `ip.addr==185.220.101.44` |
| **E-05** | Movimiento lateral RDP/SMB IT→OT | `tcp.port==3389 || tcp.port==445` |
| **E-06** | DNS tunneling / balizado C2 | `dns.qry.name contains "update-svc-atacama"` |
| **E-07** | Escritura Modbus no autorizada | `modbus.func_code == 6 || modbus.func_code == 16` |
| **E-08** | Intento STOP CPU (S7comm) | `s7comm` |
| **E-09** | Exfiltración HTTPS desde historiador | `ip.src==10.40.1.20 && tcp.dstport==443` |
| IoC C2 | Tráfico al C2 | `ip.addr==45.137.21.190` |

> En algunas versiones de Wireshark el campo Modbus es `mbtcp.modbus.func_code`; si un filtro no valida, usa `modbus.func_code`.

---

## Triage rápido con tshark / Zeek

```bash
# Jerarquía de protocolos
tshark -r minergia_ot_mayo2026.pcap -q -z io,phs

# Escrituras Modbus (FC06/FC16) — comandos peligrosos
tshark -r minergia_ot_mayo2026.pcap -Y "modbus.func_code==6 || modbus.func_code==16" \
       -T fields -e frame.time -e ip.src -e ip.dst -e modbus.func_code

# DNS sospechoso (etiquetas largas)
tshark -r minergia_ot_mayo2026.pcap -Y "dns.flags.response==0" \
       -T fields -e dns.qry.name | awk 'length>50' | sort | uniq -c | sort -rn

# Con Zeek
zeek -r minergia_ot_mayo2026.pcap
cat conn.log | zeek-cut id.orig_h id.resp_h id.resp_p proto service | sort | uniq -c | sort -rn | head
```

---

## Preguntas guía para el estudiante

1. Identifica el **host pivote** y justifica con tres evidencias del PCAP.
2. Reconstruye la **cyber kill chain ICS** y mapéala a MITRE ATT&CK for ICS.
3. ¿Qué función Modbus representa un **riesgo de manipulación de proceso** y por qué? Localiza el paquete exacto.
4. ¿Qué control del **Plan Director (Parte 1)** habría detenido el evento E-05? ¿Y el E-07?
5. Calcula el **MTTD** implícito (primer indicio E-01 → escritura E-07) y discútelo frente a la meta del Plan (&lt; 15 min).
6. Propón **tres reglas Suricata/Zeek** que habrían alertado esta campaña en tiempo real.
