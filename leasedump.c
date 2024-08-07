/*!
 * leasedump.c - dhcp lease dumper
 * Copyright (c) 2024, Christopher Jeffrey (MIT License).
 * https://github.com/chjj/leasedump
 *
 * Parts of this software are based on dhcpdump:
 *   Copyright (c) 2001-2024, Edwin Groothuis (BSD 2-Clause).
 *   Copyright (c) 2023-2024, Boian Bonev (BSD 2-Clause).
 *   https://github.com/bbonev/dhcpdump
 *
 * See LICENSE for more information.
 *
 * DHCPv4 Resources:
 *   https://en.wikipedia.org/wiki/Dynamic_Host_Configuration_Protocol
 *   https://datatracker.ietf.org/doc/html/rfc2131
 *   https://datatracker.ietf.org/doc/html/rfc2132
 *   https://github.com/bbonev/dhcpdump/blob/master/dhcpdump.c
 *
 * DHCPv6 Resources:
 *   https://en.wikipedia.org/wiki/DHCPv6
 *   https://datatracker.ietf.org/doc/html/rfc8415
 */

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* ssize_t */
#include <sys/stat.h> /* fstat, S_* */
#include <fcntl.h> /* open, O_* */
#include <unistd.h> /* read, close */

/*
 * Macros
 */

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

#define SPERW (7 * 24 * 3600)
#define SPERD (24 * 3600)
#define SPERH (3600)
#define SPERM (60)

/*
 * Constants
 */

/* The first comment is the number, the last parameter is if it's verbosed */
static const char *dhcp_options[] = {
/*   0 */ "pad",
/*   1 */ "Subnet mask",
/*   2 */ "Time offset",
/*   3 */ "Router",
/*   4 */ "Time server",
/*   5 */ "Name server",
/*   6 */ "DNS server",
/*   7 */ "Log server",
/*   8 */ "Quotes server",
/*   9 */ "LPR server",
/*  10 */ "Impress server",
/*  11 */ "RLP server",
/*  12 */ "Hostname",
/*  13 */ "Boot file size",
/*  14 */ "Merit dump file",
/*  15 */ "Domain name",
/*  16 */ "Swap server",
/*  17 */ "Root path",
/*  18 */ "Extensions path",
/*  19 */ "IP forwarding",
/*  20 */ "Non-local source routing",
/*  21 */ "Policy filter",
/*  22 */ "Maximum datagram reassembly size",
/*  23 */ "Default IP TTL",
/*  24 */ "Path MTU aging timeout",
/*  25 */ "Path MTU plateau table",
/*  26 */ "Interface MTU size",
/*  27 */ "All subnets local",
/*  28 */ "Broadcast address",
/*  29 */ "Perform mask discovery",
/*  30 */ "Mask supplier",
/*  31 */ "Perform router discovery",
/*  32 */ "Router solicitation",
/*  33 */ "Static route",
/*  34 */ "Trailer encapsulation",
/*  35 */ "ARP cache timeout",
/*  36 */ "Ethernet encapsulation",
/*  37 */ "TCP default TTL",
/*  38 */ "TCP keepalive interval",
/*  39 */ "TCP keepalive garbage",
/*  40 */ "NIS domain",
/*  41 */ "NIS servers",
/*  42 */ "NTP servers",
/*  43 */ "Vendor specific info",
/*  44 */ "NetBIOS name server",
/*  45 */ "NetBIOS datagram distribution server",
/*  46 */ "NetBIOS node type",
/*  47 */ "NetBIOS scope",
/*  48 */ "X Window System font server",
/*  49 */ "X Window System display server",
/*  50 */ "Requested IP address",
/*  51 */ "IP address leasetime",
/*  52 */ "Option overload",
/*  53 */ "DHCP message type",
/*  54 */ "DHCP Server identifier",
/*  55 */ "Parameter Request List",
/*  56 */ "DHCP Error Message",
/*  57 */ "Maximum DHCP message size",
/*  58 */ "Renewal Time T1",
/*  59 */ "Rebinding Time T2",
/*  60 */ "Vendor class identifier",
/*  61 */ "Client-identifier",
/*  62 */ "Netware/IP domain name",
/*  63 */ "Netware/IP sub options",
/*  64 */ "NIS+ domain",
/*  65 */ "NIS+ servers",
/*  66 */ "TFTP server name",
/*  67 */ "Bootfile name",
/*  68 */ "Mobile IP home agent",
/*  69 */ "SMTP server",
/*  70 */ "POP3 server",
/*  71 */ "NNTP server",
/*  72 */ "WWW server",
/*  73 */ "Finger server",
/*  74 */ "IRC server",
/*  75 */ "StreetTalk server",
/*  76 */ "StreetTalk directory assistance server",
/*  77 */ "User-class Identification",
/*  78 */ "SLP-directory-agent",
/*  79 */ "SLP-service-scope",
/*  80 */ "Rapid Commit / Naming Authority",
/*  81 */ "Client FQDN",
/*  82 */ "Relay Agent Information",
/*  83 */ "Internet Storage Name Service",
/*  84 */ "REMOVED/Unassigned",
/*  85 */ "NDS server",
/*  86 */ "NDS tree name",
/*  87 */ "NDS context",
/*  88 */ "BCMCS Controller Domain Name list",
/*  89 */ "BCMCS Controller IPv4 address option",
/*  90 */ "Authentication",
/*  91 */ "Client-last-transaction-time",
/*  92 */ "Associated-ip",
/*  93 */ "Client System",
/*  94 */ "Client NDI",
/*  95 */ "LDAP",
/*  96 */ "REMOVED/Unassigned",
/*  97 */ "UUID/GUID",
/*  98 */ "Open Group's User Authentication",
/*  99 */ "GEOCONF_CIVIC",
/* 100 */ "PCode - IEEE 1003.1 TZ String",
/* 101 */ "TCode - Reference to the TZ Database",
/* 102 */ "REMOVED/Unassigned",
/* 103 */ "REMOVED/Unassigned",
/* 104 */ "REMOVED/Unassigned",
/* 105 */ "REMOVED/Unassigned",
/* 106 */ "REMOVED/Unassigned",
/* 107 */ "REMOVED/Unassigned",
/* 108 */ "IPv6-Only Preferred",
/* 109 */ "DHCPv4 over DHCPv6 Source Address",
/* 110 */ "REMOVED/Unassigned",
/* 111 */ "???",
/* 112 */ "Netinfo Address",
/* 113 */ "Netinfo Tag",
/* 114 */ "DHCP Captive-Portal",
/* 115 */ "REMOVED/Unassigned",
/* 116 */ "DHCP Autoconfiguration",
/* 117 */ "Name Service Search",
/* 118 */ "Subnet selection",
/* 119 */ "Domain Search",
/* 120 */ "SIP Servers DHCP Option",
/* 121 */ "Classless Static Route",
/* 122 */ "CableLabs Client Configuration",
/* 123 */ "GeoConf Option",
/* 124 */ "V-I Vendor Class",
/* 125 */ "V-I Vendor-Specific Info",
/* 126 */ "REMOVED/Unassigned",
/* 127 */ "REMOVED/Unassigned",
/* 128 */ "PXE/Etherboot signature/DOCSIS",
/* 129 */ "PXE/Kernel options/Call server IP",
/* 130 */ "PXE/Ethernet interface",
/* 131 */ "PXE/Remote statistics server",
/* 132 */ "PXE/802.1Q VLAN ID",
/* 133 */ "PXE/802.1D/p Layer 2 Priority",
/* 134 */ "PXE/Diffserv Code Point for VoIP",
/* 135 */ "PXE/HTTP Proxy for phone",
/* 136 */ "OPTION_PANA_AGENT",
/* 137 */ "OPTION_V4_LOST",
/* 138 */ "OPTION_CAPWAP_AC_V4",
/* 139 */ "OPTION-IPv4_Address-MoS",
/* 140 */ "OPTION-IPv4_FQDN-MoS",
/* 141 */ "SIP UA Configuration SDomains",
/* 142 */ "OPTION-IPv4_Address-ANDSF",
/* 143 */ "OPTION_V4_SZTP_REDIRECT",
/* 144 */ "GeoLoc/HP - TFTP file",
/* 145 */ "FORCERENEW_NONCE_CAPABLE",
/* 146 */ "RDNSS Selection",
/* 147 */ "OPTION_V4_DOTS_RI",
/* 148 */ "OPTION_V4_DOTS_ADDRESS",
/* 149 */ "???",
/* 150 */ "TFTP server address/Etherboot/GRUB path",
/* 151 */ "status-code",
/* 152 */ "base-time",
/* 153 */ "start-time-of-state",
/* 154 */ "query-start-time",
/* 155 */ "query-end-time",
/* 156 */ "dhcp-state",
/* 157 */ "data-source",
/* 158 */ "OPTION_V4_PCP_SERVER",
/* 159 */ "OPTION_V4_PORTPARAMS",
/* 160 */ "???",
/* 161 */ "OPTION_MUD_URL_V4",
/* 162 */ "OPTION_V4_DNR",
/* 163 */ "???",
/* 164 */ "???",
/* 165 */ "???",
/* 166 */ "???",
/* 167 */ "???",
/* 168 */ "???",
/* 169 */ "???",
/* 170 */ "???",
/* 171 */ "???",
/* 172 */ "???",
/* 173 */ "???",
/* 174 */ "???",
/* 175 */ "Etherboot (Tentatively 2005-06-23)",
/* 176 */ "IP Telephone (Tentatively 2005-06-23)",
/* 177 */ "Etherboot (Tentatively 2005-06-23)",
/* 178 */ "???",
/* 179 */ "???",
/* 180 */ "???",
/* 181 */ "???",
/* 182 */ "???",
/* 183 */ "???",
/* 184 */ "???",
/* 185 */ "???",
/* 186 */ "???",
/* 187 */ "???",
/* 188 */ "???",
/* 189 */ "???",
/* 190 */ "???",
/* 191 */ "???",
/* 192 */ "???",
/* 193 */ "???",
/* 194 */ "???",
/* 195 */ "???",
/* 196 */ "???",
/* 197 */ "???",
/* 198 */ "???",
/* 199 */ "???",
/* 200 */ "???",
/* 201 */ "???",
/* 202 */ "???",
/* 203 */ "???",
/* 204 */ "???",
/* 205 */ "???",
/* 206 */ "???",
/* 207 */ "???",
/* 208 */ "PXELINUX Magic",
/* 209 */ "Configuration File",
/* 210 */ "Path Prefix",
/* 211 */ "Reboot Time",
/* 212 */ "OPTION_6RD",
/* 213 */ "OPTION_V4_ACCESS_DOMAIN",
/* 214 */ "???",
/* 215 */ "???",
/* 216 */ "???",
/* 217 */ "???",
/* 218 */ "???",
/* 219 */ "???",
/* 220 */ "Subnet Allocation",
/* 221 */ "Virtual Subnet Selection",
/* 222 */ "???",
/* 223 */ "???",
/* 224 */ "Reserved for private use",
/* 225 */ "Reserved for private use",
/* 226 */ "Reserved for private use",
/* 227 */ "Reserved for private use",
/* 228 */ "Reserved for private use",
/* 229 */ "Reserved for private use",
/* 230 */ "Reserved for private use",
/* 231 */ "Reserved for private use",
/* 232 */ "Reserved for private use",
/* 233 */ "Reserved for private use",
/* 234 */ "Reserved for private use",
/* 235 */ "Reserved for private use",
/* 236 */ "Reserved for private use",
/* 237 */ "Reserved for private use",
/* 238 */ "Reserved for private use",
/* 239 */ "Reserved for private use",
/* 240 */ "Reserved for private use",
/* 241 */ "Reserved for private use",
/* 242 */ "Reserved for private use",
/* 243 */ "Reserved for private use",
/* 244 */ "Reserved for private use",
/* 245 */ "Reserved for private use",
/* 246 */ "Reserved for private use",
/* 247 */ "Reserved for private use",
/* 248 */ "Reserved for private use",
/* 249 */ "MSFT - Classless route",
/* 250 */ "Reserved for private use",
/* 251 */ "Reserved for private use",
/* 252 */ "MSFT - WinSock Proxy Auto Detect",
/* 253 */ "Reserved for private use",
/* 254 */ "Reserved for private use",
/* 255 */ "End"
};

static const char *dhcp_message_types[] = {
/*   0 */ "undefined",
/*   1 */ "DHCPDISCOVER",
/*   2 */ "DHCPOFFER",
/*   3 */ "DHCPREQUEST",
/*   4 */ "DHCPDECLINE",
/*   5 */ "DHCPACK",
/*   6 */ "DHCPNAK",
/*   7 */ "DHCPRELEASE",
/*   8 */ "DHCPINFORM",
/*   9 */ "DHCPFORCERENEW",
/*  10 */ "DHCPLEASEQUERY",
/*  11 */ "DHCPLEASEUNASSIGNED",
/*  12 */ "DHCPLEASEUNKNOWN",
/*  13 */ "DHCPLEASEACTIVE",
/*  14 */ "DHCPBULKLEASEQUERY",
/*  15 */ "DHCPLEASEQUERYDONE",
/*  16 */ "DHCPACTIVELEASEQUERY",
/*  17 */ "DHCPLEASEQUERYSTATUS",
/*  18 */ "DHCPTLS"
};

static const char *operands[] = {
/*   0 */ "undefined",
/*   1 */ "BOOTPREQUEST",
/*   2 */ "BOOTPREPLY"
};

/* Copied from RFC1700 */
static const char *htypes[] = {
/*   0 */ "undefined",
/*   1 */ "Ethernet",
/*   2 */ "Experimental Ethernet",
/*   3 */ "Amateur Radio AX.25",
/*   4 */ "Proteon ProNET Token Ring",
/*   5 */ "Chaos",
/*   6 */ "IEEE 802 Networks",
/*   7 */ "ARCNET",
/*   8 */ "Hyperchannel",
/*   9 */ "Lanstar",
/*  10 */ "Autonet Short Address",
/*  11 */ "LocalTalk",
/*  12 */ "LocalNet",
/*  13 */ "Ultra link",
/*  14 */ "SMDS",
/*  15 */ "Frame Relay",
/*  16 */ "ATM",
/*  17 */ "HDLC",
/*  18 */ "Fibre Channel",
/*  19 */ "ATM",
/*  20 */ "Serial Line",
/*  21 */ "ATM",
/*  22 */ "MIL-STD-188-220",
/*  23 */ "Metricom",
/*  24 */ "IEEE 1394.1995",
/*  25 */ "MAPOS",
/*  26 */ "Twinaxial",
/*  27 */ "EUI-64",
/*  28 */ "HIPARP",
/*  29 */ "IP and ARP over ISO 7816-3",
/*  30 */ "ARPSec",
/*  31 */ "IPsec tunnel",
/*  32 */ "InfiniBand",
/*  33 */ "TIA-102 Project 25 Common Air Interface",
/*  34 */ "Wiegand Interface",
/*  35 */ "Pure IP",
/*  36 */ "HW_EXP1",
/*  37 */ "HFI",
/*  38 */ "Unified Bus"
};

/* https://datatracker.ietf.org/doc/html/rfc8415#section-7.3 */
static const char *operands6[] = {
/*   0 */ "undefined",
/*   1 */ "SOLICIT",
/*   2 */ "ADVERTISE",
/*   3 */ "REQUEST",
/*   4 */ "CONFIRM",
/*   5 */ "RENEW",
/*   6 */ "REBIND",
/*   7 */ "REPLY",
/*   8 */ "RELEASE",
/*   9 */ "DECLINE",
/*  10 */ "RECONFIGURE",
/*  11 */ "INFORMATION-REQUEST",
/*  12 */ "RELAY-FORW",
/*  13 */ "RELAY-REPL",
/*  14 */ "LEASEQUERY",
/*  15 */ "LEASEQUERY-REPLY",
/*  16 */ "LEASEQUERY-DONE",
/*  17 */ "LEASEQUERY-DATA",
/*  18 */ "RECONFIGURE-REQUEST",
/*  19 */ "RECONFIGURE-REPLY",
/*  20 */ "DHCPV4-QUERY",
/*  21 */ "DHCPV4-RESPONSE",
/*  22 */ "ACTIVELEASEQUERY",
/*  23 */ "STARTTLS"
};

/* https://datatracker.ietf.org/doc/html/rfc8415#section-21 */
static const char *dhcp_options6[] = {
/*   0 */ "undefined",
/*   1 */ "CLIENTID",
/*   2 */ "SERVERID",
/*   3 */ "IA_NA",
/*   4 */ "IA_TA",
/*   5 */ "IAADDR",
/*   6 */ "ORO",
/*   7 */ "PREFERENCE",
/*   8 */ "ELAPSED_TIME",
/*   9 */ "RELAY_MSG",
/*  10 */ "REMOVED/Unassigned",
/*  11 */ "AUTH",
/*  12 */ "UNICAST",
/*  13 */ "STATUS_CODE",
/*  14 */ "RAPID_COMMIT",
/*  15 */ "USER_CLASS",
/*  16 */ "VENDOR_CLASS",
/*  17 */ "VENDOR_OPTS",
/*  18 */ "INTERFACE_ID",
/*  19 */ "RECONF_MSG",
/*  20 */ "RECONF_ACCEPT",
/*  21 */ "SIP_SERVER_D",
/*  22 */ "SIP_SERVER_A",
/*  23 */ "DNS_SERVERS",
/*  24 */ "DOMAIN_LIST",
/*  25 */ "IA_PD",
/*  26 */ "IAPREFIX",
/*  27 */ "NIS_SERVERS",
/*  28 */ "NISP_SERVERS",
/*  29 */ "NIS_DOMAIN_NAME",
/*  30 */ "NISP_DOMAIN_NAME",
/*  31 */ "SNTP_SERVERS",
/*  32 */ "INFORMATION_REFRESH_TIME",
/*  33 */ "BCMCS_SERVER_D",
/*  34 */ "BCMCS_SERVER_A",
/*  35 */ "REMOVED/Unassigned",
/*  36 */ "GEOCONF_CIVIC",
/*  37 */ "REMOTE_ID",
/*  38 */ "SUBSCRIBER_ID",
/*  39 */ "CLIENT_FQDN",
/*  40 */ "PANA_AGENT",
/*  41 */ "NEW_POSIX_TIMEZONE",
/*  42 */ "NEW_TZDB_TIMEZONE",
/*  43 */ "ERO",
/*  44 */ "LQ_QUERY",
/*  45 */ "CLIENT_DATA",
/*  46 */ "CLT_TIME",
/*  47 */ "LQ_RELAY_DATA",
/*  48 */ "LQ_CLIENT_LINK",
/*  49 */ "MIP6_HNIDF",
/*  50 */ "MIP6_VDINF",
/*  51 */ "V6_LOST",
/*  52 */ "CAPWAP_AC_V6",
/*  53 */ "RELAY_ID",
/*  54 */ "IPv6_Address-MoS",
/*  55 */ "IPv6_FQDN-MoS",
/*  56 */ "NTP_SERVER",
/*  57 */ "V6_ACCESS_DOMAIN",
/*  58 */ "SIP_UA_CS_LIST",
/*  59 */ "OPT_BOOTFILE_URL",
/*  60 */ "OPT_BOOTFILE_PARAM",
/*  61 */ "CLIENT_ARCH_TYPE",
/*  62 */ "NII",
/*  63 */ "GEOLOCATION",
/*  64 */ "AFTR_NAME",
/*  65 */ "ERP_LOCAL_DOMAIN_NAME",
/*  66 */ "RSOO",
/*  67 */ "PD_EXCLUDE",
/*  68 */ "VSS",
/*  69 */ "MIP6_IDINF",
/*  70 */ "MIP6_UDINF",
/*  71 */ "MIP6_HNP",
/*  72 */ "MIP6_HAA",
/*  73 */ "MIP6_HAF",
/*  74 */ "RDNSS_SELECTION",
/*  75 */ "KRB_PRINCIPAL_NAME",
/*  76 */ "KRB_REALM_NAME",
/*  77 */ "KRB_DEFAULT_REALM_NAME",
/*  78 */ "KRB_KDC",
/*  79 */ "CLIENT_LINKLAYER_ADDR",
/*  80 */ "LINK_ADDRESS",
/*  81 */ "RADIUS",
/*  82 */ "SOL_MAX_RT",
/*  83 */ "INF_MAX_RT",
/*  84 */ "ADDRSEL",
/*  85 */ "ADDRSEL_TABLE",
/*  86 */ "V6_PCP_SERVER",
/*  87 */ "DHCPV4_MSG",
/*  88 */ "DHCP4_O_DHCP6_SERVER",
/*  89 */ "S46_RULE",
/*  90 */ "S46_BR",
/*  91 */ "S46_DMR",
/*  92 */ "S46_V4V6BIND",
/*  93 */ "S46_PORTPARAMS",
/*  94 */ "S46_CONT_MAPE",
/*  95 */ "S46_CONT_MAPT",
/*  96 */ "S46_CONT_LW",
/*  97 */ "4RD",
/*  98 */ "4RD_MAP_RULE",
/*  99 */ "4RD_NON_MAP_RULE",
/* 100 */ "LQ_BASE_TIME",
/* 101 */ "LQ_START_TIME",
/* 102 */ "LQ_END_TIME",
/* 103 */ "DHCP Captive-Portal",
/* 104 */ "MPL_PARAMETERS",
/* 105 */ "ANI_ATT",
/* 106 */ "ANI_NETWORK_NAME",
/* 107 */ "ANI_AP_NAME",
/* 108 */ "ANI_AP_BSSID",
/* 109 */ "ANI_OPERATOR_ID",
/* 110 */ "ANI_OPERATOR_REALM",
/* 111 */ "S46_PRIORITY",
/* 112 */ "MUD_URL_V6",
/* 113 */ "V6_PREFIX64",
/* 114 */ "F_BINDING_STATUS",
/* 115 */ "F_CONNECT_FLAGS",
/* 116 */ "F_DNS_REMOVAL_INFO",
/* 117 */ "F_DNS_HOST_NAME",
/* 118 */ "F_DNS_ZONE_NAME",
/* 119 */ "F_DNS_FLAGS",
/* 120 */ "F_EXPIRATION_TIME",
/* 121 */ "F_MAX_UNACKED_BNDUPD",
/* 122 */ "F_MCLT",
/* 123 */ "F_PARTNER_LIFETIME",
/* 124 */ "F_PARTNER_LIFETIME_SENT",
/* 125 */ "F_PARTNER_DOWN_TIME",
/* 126 */ "F_PARTNER_RAW_CLT_TIME",
/* 127 */ "F_PROTOCOL_VERSION",
/* 128 */ "F_KEEPALIVE_TIME",
/* 129 */ "F_RECONFIGURE_DATA",
/* 130 */ "F_RELATIONSHIP_NAME",
/* 131 */ "F_SERVER_FLAGS",
/* 132 */ "F_SERVER_STATE",
/* 133 */ "F_START_TIME_OF_STATE",
/* 134 */ "F_STATE_EXPIRATION_TIME",
/* 135 */ "RELAY_PORT",
/* 136 */ "???",
/* 137 */ "???",
/* 138 */ "???",
/* 139 */ "???",
/* 140 */ "???",
/* 141 */ "???",
/* 142 */ "???",
/* 143 */ "IPv6_Address-ANDSF",
/* 144 */ "???",
/* 145 */ "???",
/* 146 */ "???",
/* 147 */ "???",
/* 148 */ "???",
/* 149 */ "???",
/* 150 */ "???",
/* 151 */ "???",
/* 152 */ "???",
/* 153 */ "???",
/* 154 */ "???",
/* 155 */ "???",
/* 156 */ "???",
/* 157 */ "???",
/* 158 */ "???",
/* 159 */ "???",
/* 160 */ "???",
/* 161 */ "???",
/* 162 */ "???",
/* 163 */ "???",
/* 164 */ "???",
/* 165 */ "???",
/* 166 */ "???",
/* 167 */ "???",
/* 168 */ "???",
/* 169 */ "???",
/* 170 */ "???",
/* 171 */ "???",
/* 172 */ "???",
/* 173 */ "???",
/* 174 */ "???",
/* 175 */ "???",
/* 176 */ "???",
/* 177 */ "???",
/* 178 */ "???",
/* 179 */ "???",
/* 180 */ "???",
/* 181 */ "???",
/* 182 */ "???",
/* 183 */ "???",
/* 184 */ "???",
/* 185 */ "???",
/* 186 */ "???",
/* 187 */ "???",
/* 188 */ "???",
/* 189 */ "???",
/* 190 */ "???",
/* 191 */ "???",
/* 192 */ "???",
/* 193 */ "???",
/* 194 */ "???",
/* 195 */ "???",
/* 196 */ "???",
/* 197 */ "???",
/* 198 */ "???",
/* 199 */ "???",
/* 200 */ "???",
/* 201 */ "???",
/* 202 */ "???",
/* 203 */ "???",
/* 204 */ "???",
/* 205 */ "???",
/* 206 */ "???",
/* 207 */ "???",
/* 208 */ "???",
/* 209 */ "???",
/* 210 */ "???",
/* 211 */ "???",
/* 212 */ "???",
/* 213 */ "???",
/* 214 */ "???",
/* 215 */ "???",
/* 216 */ "???",
/* 217 */ "???",
/* 218 */ "???",
/* 219 */ "???",
/* 220 */ "???",
/* 221 */ "???",
/* 222 */ "???",
/* 223 */ "???",
/* 224 */ "???",
/* 225 */ "???",
/* 226 */ "???",
/* 227 */ "???",
/* 228 */ "???",
/* 229 */ "???",
/* 230 */ "???",
/* 231 */ "???",
/* 232 */ "???",
/* 233 */ "???",
/* 234 */ "???",
/* 235 */ "???",
/* 236 */ "???",
/* 237 */ "???",
/* 238 */ "???",
/* 239 */ "???",
/* 240 */ "???",
/* 241 */ "???",
/* 242 */ "???",
/* 243 */ "???",
/* 244 */ "???",
/* 245 */ "???",
/* 246 */ "???",
/* 247 */ "???",
/* 248 */ "???",
/* 249 */ "???",
/* 250 */ "???",
/* 251 */ "???",
/* 252 */ "???",
/* 253 */ "???",
/* 254 */ "???",
/* 255 */ "???"
};

static void
print_string(const unsigned char *xp, size_t xn) {
  while (xn > 0 && *xp != 0) {
    int ch = *xp;

    if (ch < ' ' || ch > '~')
      printf("\\x%02x", ch);
    else
      putchar(ch);

    xp++;
    xn--;
  }
}

static void
print_hex(const unsigned char *xp, size_t xn) {
  while (xn--)
    printf("%02x", *xp++);
}

static void
print_hex_colon(const unsigned char *xp, size_t xn) {
  size_t i;

  for (i = 0; i < xn; i++) {
    if (i != 0)
      printf(":");
    printf("%02x", xp[i]);
  }
}

static void
print_addr4(const unsigned char *xp) {
  printf("%u.%u.%u.%u", xp[0], xp[1], xp[2], xp[3]);
}

/**
 * Portable inet_{pton,ntop}.
 *
 * Code from libuv[1]. According to c-ares[2][3], this code was
 * written in 1996 by Paul Vixie and is under the ISC license.
 *
 * See LICENSE for more information.
 *
 * [1] https://github.com/libuv/libuv/blob/385b796/src/inet.c
 * [2] https://github.com/c-ares/c-ares/blob/c2f3235/src/lib/inet_ntop.c
 * [3] https://github.com/c-ares/c-ares/blob/c2f3235/src/lib/inet_net_pton.c
 */

static int
inet_ntop4(const unsigned char *src, char *dst, size_t size) {
  static const char fmt[] = "%u.%u.%u.%u";
  char tmp[4 * 10 + 3 + 1];
  int c;

  c = sprintf(tmp, fmt, src[0], src[1], src[2], src[3]);

  if (c <= 0 || (size_t)c + 1 > size)
    return -1;

  memcpy(dst, tmp, c + 1);

  return 0;
}

static int
inet_ntop6(const unsigned char *src, char *dst, size_t size) {
  /*
   * Note that int32_t and int16_t need only be "at least" large enough
   * to contain a value of the specified size.  On some systems, like
   * Crays, there is no such thing as an integer variable with 16 bits.
   * Keep this in mind if you think this function should have been coded
   * to use pointer overlays.  All the world's not a VAX.
   */
  struct { int base, len; } best, cur;
  char tmp[65 + 14 + 1], *tp;
  unsigned int words[16 / 2];
  int i;

  /*
   * Preprocess:
   *  Copy the input (bytewise) array into a wordwise array.
   *  Find the longest run of 0x00's in src[] for :: shorthanding.
   */
  memset(words, 0, sizeof(words));

  for (i = 0; i < 16; i++)
    words[i / 2] |= (src[i] << ((1 - (i % 2)) << 3));

  best.base = -1;
  best.len = 0;
  cur.base = -1;
  cur.len = 0;

  for (i = 0; i < (int)lengthof(words); i++) {
    if (words[i] == 0) {
      if (cur.base == -1) {
        cur.base = i;
        cur.len = 1;
      } else {
        cur.len++;
      }
    } else {
      if (cur.base != -1) {
        if (best.base == -1 || cur.len > best.len)
          best = cur;

        cur.base = -1;
      }
    }
  }

  if (cur.base != -1) {
    if (best.base == -1 || cur.len > best.len)
      best = cur;
  }

  if (best.base != -1 && best.len < 2)
    best.base = -1;

  /*
   * Format the result.
   */
  tp = tmp;

  for (i = 0; i < (int)lengthof(words); i++) {
    /* Are we inside the best run of 0x00's? */
    if (best.base != -1 && i >= best.base && i < (best.base + best.len)) {
      if (i == best.base)
        *tp++ = ':';

      continue;
    }

    /* Are we following an initial run of 0x00s or any real hex? */
    if (i != 0)
      *tp++ = ':';

    /* Is this address an encapsulated IPv4? */
    if (i == 6 && best.base == 0 && (best.len == 6
        || (best.len == 7 && words[7] != 0x0001)
        || (best.len == 5 && words[5] == 0xffff))) {
      int err = inet_ntop4(src + 12, tp, sizeof(tmp) - (tp - tmp));

      if (err)
        return err;

      tp += strlen(tp);

      break;
    }

    tp += sprintf(tp, "%x", words[i]);
  }

  /* Was it a trailing run of 0x00's? */
  if (best.base != -1 && (best.base + best.len) == lengthof(words))
    *tp++ = ':';

  *tp++ = '\0';

  if ((size_t)(tp - tmp) > size)
    return -1;

  memcpy(dst, tmp, tp - tmp);

  return 0;
}

static void
print_addr6(const unsigned char *xp) {
  char buf[128];

  if (inet_ntop6(xp, buf, sizeof(buf)) != 0)
    abort();

  printf("%s", buf);
}

static void
print_time32(const unsigned char *xp) {
  unsigned int ts = ((unsigned int)xp[0] << 24)
                  | ((unsigned int)xp[1] << 16)
                  | ((unsigned int)xp[2] <<  8)
                  | ((unsigned int)xp[3] <<  0);

  printf("%u (", ts);

  if (ts > SPERW) {
    printf("%uw", ts / SPERW);
    ts %= SPERW;
  }

  if (ts > SPERD) {
    printf("%ud", ts / SPERD);
    ts %= SPERD;
  }

  if (ts > SPERH) {
    printf("%uh", ts / SPERH);
    ts %= SPERH;
  }

  if (ts > SPERM) {
    printf("%um", ts / SPERM);
    ts %= SPERM;
  }

  if (ts > 0)
    printf("%us", ts);

  printf(")");
}

static int
print_lease(const unsigned char *xp, size_t xn) {
  int rc = 0;

  if (xn < 240)
    return 0;

  if (xp[0] >= lengthof(operands))
    return 0;

  if (xp[1] >= lengthof(htypes))
    return 0;

  printf("    OP: %d (%s)\n", xp[0], operands[xp[0]]);
  printf(" HTYPE: %d (%s)\n", xp[1], htypes[xp[1]]);
  printf("  HLEN: %d\n", xp[2]);
  printf("  HOPS: %d\n", xp[3]);
  printf("   XID: %02x%02x%02x%02x\n", xp[4], xp[5], xp[6], xp[7]);
  printf("  SECS: %u", (xp[8] << 8) | xp[9]);
  printf("\n");
  printf(" FLAGS: %x\n", (xp[10] << 8) | xp[11]);
  printf("CIADDR: ");
  print_addr4(xp + 12);
  printf("\n");
  printf("YIADDR: ");
  print_addr4(xp + 16);
  printf("\n");
  printf("SIADDR: ");
  print_addr4(xp + 20);
  printf("\n");
  printf("GIADDR: ");
  print_addr4(xp + 24);
  printf("\n");
  printf("CHADDR: ");
  print_hex_colon(xp + 28, 16);
  printf("\n");
  printf(" SNAME: ");
  print_string(xp + 44, 64);
  printf(".\n");
  printf(" FNAME: ");
  print_string(xp + 108, 128);
  printf(".\n");

  xp += 240;
  xn -= 240;

  while (xn > 0 && *xp != 255) {
    int opt = *xp;
    size_t len;

    xp += 1;
    xn -= 1;

    if (opt == 0) /* Padding */
      continue;

    if (xn == 0)
      break;

    len = *xp;

    xp += 1;
    xn -= 1;

    if (xn < len)
      break;

    rc = 1;

    printf("OPTION: %3d (%3d) %-26s", opt, (int)len, dhcp_options[opt]);

    switch (opt) {
      case 1: /* Subnetmask */
      case 16: /* Swap server */
      case 28: /* Broadcast address */
      case 32: /* Router solicitation */
      case 50: /* Requested IP address */
      case 54: /* Server identifier */
      case 118: { /* Subnet selection option */
        if (len >= 4)
          print_addr4(xp);
        break;
      }

      case 12: /* Hostname */
      case 14: /* Merit dump file */
      case 15: /* Domain name */
      case 17: /* Root Path */
      case 18: /* Extensions path */
      case 40: /* NIS domain */
      case 56: /* Message */
      case 62: /* Netware/IP domain name */
      case 64: /* NIS+ domain */
      case 66: /* TFTP server name */
      case 67: /* bootfile name */
      case 86: /* NDS Tree name */
      case 87: /* NDS context */
      case 100: /* PCode - TZ-Posix String */
      case 101: /* TCode - TX-Database String */
      case 114: /* Captive-portal */
      case 147: { /* DOTS Reference Identifier */
        print_string(xp, len);
        break;
      }

      case 3: /* Routers */
      case 4: /* Time servers */
      case 5: /* Name servers */
      case 6: /* DNS server */
      case 7: /* Log server */
      case 8: /* Cookie server */
      case 9: /* LPR server */
      case 10: /* Impress server */
      case 11: /* Resource location server */
      case 41: /* NIS servers */
      case 42: /* NTP servers */
      case 44: /* NetBIOS name server */
      case 45: /* NetBIOS datagram distribution server */
      case 48: /* X Window System font server */
      case 49: /* X Window System display server */
      case 65: /* NIS+ servers */
      case 68: /* Mobile IP home agent */
      case 69: /* SMTP server */
      case 70: /* POP3 server */
      case 71: /* NNTP server */
      case 72: /* WWW server */
      case 73: /* Finger server */
      case 74: /* IRC server */
      case 75: /* StreetTalk server */
      case 76: /* StreetTalk directory assistance server */
      case 78: /* Directory Agent */
      case 85: /* NDS server */
      case 92: /* Associated IP */
      case 148: /* DOTS Address */
      case 150: /* TFTP server address */
      case 162: { /* Encrypted DNS Server */
        size_t i;

        for (i = 0; i < (len >> 2); i++) {
          if (i != 0)
            printf(",");
          print_addr4(xp);
          xp += 4;
          xn -= 4;
        }

        len &= 3;

        break;
      }

      case 53: { /* DHCP message type */
        const char *name = "*unknown*";
        unsigned int type;

        if (len < 1)
          break;

        type = *xp;

        if (type < lengthof(dhcp_message_types))
          name = dhcp_message_types[type];

        printf("%u (%s)", type, name);

        break;
      }

      case 2: /* Time offset */
      case 24: /* Path MTU aging timeout */
      case 35: /* ARP cache timeout */
      case 38: /* TCP keepalive interval */
      case 51: /* IP address leasetime */
      case 58: /* T1 */
      case 59: /* T2 */
      case 91: /* Client last transaction time */
      case 108: /* IPv6-Only preferred */
      case 152: /* base-time */
      case 153: /* start-time-of-state */
      case 154: /* query-start-time */
      case 155: /* query-end-time */
      case 211: { /* reboot-time */
        if (len >= 4)
          print_time32(xp);
        break;
      }

      default: {
        print_hex(xp, len);
        break;
      }
    }

    printf("\n");

    xp += len;
    xn -= len;
  }

  fflush(stdout);

  return rc;
}

static int
print_lease6(const unsigned char *xp, size_t xn) {
  int rc = 0;

  if (xn < 4)
    return 0;

  if (xp[0] >= lengthof(operands6))
    return 0;

  printf(" TYPE: %d (%s)\n", xp[0], operands6[xp[0]]);
  printf(" TXID: %x\n", (xp[1] << 16) | (xp[2] << 8) | xp[3]);

  xp += 4;
  xn -= 4;

  while (xn >= 2) {
    const char *optname = "*unknown*";
    int opt = (xp[0] << 8) | xp[1];
    size_t len;

    xp += 2;
    xn -= 2;

    if (xn < 2)
      break;

    len = (xp[0] << 8) | xp[1];

    xp += 2;
    xn -= 2;

    if (xn < len)
      break;

    rc = 1;

    if (opt < (int)lengthof(dhcp_options6))
      optname = dhcp_options6[opt];

    printf("OPTION: %3d (%3d) %-26s", opt, (int)len, optname);

    switch (opt) {
      case 1: /* CLIENTID */
      case 2: /* SERVERID */ {
        print_hex_colon(xp, len);
        break;
      }

      case 23: { /* DNS_SERVERS */
        size_t i;

        for (i = 0; i < (len >> 4); i++) {
          if (i != 0)
            printf(",");
          print_addr6(xp);
          xp += 16;
          xn -= 16;
        }

        len &= 15;

        break;
      }

      case 24: { /* DOMAIN_LIST */
        const unsigned char *tp = xp;
        size_t tn = len;
        int com = 0;

        while (tn > 0) {
          size_t c = *tp;

          tp += 1;
          tn -= 1;

          if (c == 0x00) {
            com = 1;
            continue;
          }

          if (c & 0xc0)
            break; /* error */

          if (tn < c)
            break; /* error */

          if (com)
            printf(",");

          print_string(tp, c);
          printf(".");

          tp += c;
          tn -= c;
        }

        break;
      }

      case 82: { /* SOL_MAX_RT */
        if (len >= 4)
          print_time32(xp);
        break;
      }

      default: {
        print_hex(xp, len);
        break;
      }
    }

    printf("\n");

    xp += len;
    xn -= len;
  }

  fflush(stdout);

  return rc;
}

static void
file_error(char **argv, const char *action) {
  const char *msg = strerror(errno);
  fprintf(stderr, "%s: cannot %s '%s': %s\n", argv[0], action, argv[1], msg);
}

static int
ends_with(const char *xp, const char *yp) {
  size_t xn = strlen(xp);
  size_t yn = strlen(yp);

  if (xn < yn)
    return 0;

  return memcmp(xp + xn - yn, yp, yn) == 0;
}

int
main(int argc, char **argv) {
  unsigned char buf[16 << 10];
  struct stat st;
  ssize_t nbytes;
  int i, rc, fd;

  for (i = 0; i < argc; i++) {
    if (argv[i] == NULL)
      return EXIT_FAILURE;
  }

  if (argc < 2) {
    fprintf(stderr, "Usage: $ %s /var/lib/dhcpcd/if-ssid.lease\n", argv[0]);
    return EXIT_FAILURE;
  }

  fd = open(argv[1], O_RDONLY);

  if (fd < 0) {
    file_error(argv, "access");
    return EXIT_FAILURE;
  }

  rc = fstat(fd, &st);

  if (rc < 0) {
    file_error(argv, "stat");
    goto fail;
  }

  nbytes = read(fd, buf, sizeof(buf));

  if (nbytes < 0) {
    file_error(argv, "read");
    goto fail;
  }

  if (nbytes != st.st_size) {
    fprintf(stderr, "Could not read %s\n", argv[1]);
    goto fail;
  }

  if (ends_with(argv[1], ".lease6") ||
      (argc > 2 && strcmp(argv[2], "-6") == 0)) {
    if (!print_lease6(buf, st.st_size)) {
      fprintf(stderr, "Could not parse %s\n", argv[1]);
      goto fail;
    }
  } else {
    if (!print_lease(buf, st.st_size)) {
      fprintf(stderr, "Could not parse %s\n", argv[1]);
      goto fail;
    }
  }

  close(fd);

  return EXIT_SUCCESS;
fail:
  close(fd);
  return EXIT_FAILURE;
}
