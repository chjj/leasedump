#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h> /* ssize_t */
#include <sys/stat.h> /* fstat, S_* */
#include <fcntl.h> /* open, O_* */
#include <unistd.h> /* read, close */

#define lengthof(x) (sizeof(x) / sizeof((x)[0]))

#define SPERW (7 * 24 * 3600)
#define SPERD (24 * 3600)
#define SPERH (3600)
#define SPERM (60)

// The first comment is the number, the last parameter is if it's verbosed
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

// Copied from RFC1700
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
  print_string(xp + 108, 64);
  printf(".\n");

  xp += 240;
  xn -= 240;

  while (xn > 0 && *xp != 255) {
    int opt = *xp;

    xp += 1;
    xn -= 1;

    if (opt == 0) /* Padding */
      continue;

    if (xn == 0)
      break;

    size_t len = *xp;

    xp += 1;
    xn -= 1;

    if (xn < len)
      break;

    rc = 1;

    printf("OPTION: %3d (%3d) %-26s", opt, (int)len, dhcp_options[opt]);

    switch (opt) {
      case 1: // Subnetmask
      case 16: // Swap server
      case 28: // Broadcast address
      case 32: // Router solicitation
      case 50: // Requested IP address
      case 54: // Server identifier
      case 118: { // Subnet selection option
        if (len >= 4)
          print_addr4(xp);
        break;
      }

      case 12: // Hostname
      case 14: // Merit dump file
      case 15: // Domain name
      case 17: // Root Path
      case 18: // Extensions path
      case 40: // NIS domain
      case 56: // Message
      case 62: // Netware/IP domain name
      case 64: // NIS+ domain
      case 66: // TFTP server name
      case 67: // bootfile name
      case 86: // NDS Tree name
      case 87: // NDS context
      case 100: // PCode - TZ-Posix String
      case 101: // TCode - TX-Database String
      case 114: // Captive-portal
      case 147: { // DOTS Reference Identifier
        print_string(xp, len);
        break;
      }

      case 3: // Routers
      case 4: // Time servers
      case 5: // Name servers
      case 6: // DNS server
      case 7: // Log server
      case 8: // Cookie server
      case 9: // LPR server
      case 10: // Impress server
      case 11: // Resource location server
      case 41: // NIS servers
      case 42: // NTP servers
      case 44: // NetBIOS name server
      case 45: // NetBIOS datagram distribution server
      case 48: // X Window System font server
      case 49: // X Window System display server
      case 65: // NIS+ servers
      case 68: // Mobile IP home agent
      case 69: // SMTP server
      case 70: // POP3 server
      case 71: // NNTP server
      case 72: // WWW server
      case 73: // Finger server
      case 74: // IRC server
      case 75: // StreetTalk server
      case 76: // StreetTalk directory assistance server
      case 78: // Directory Agent
      case 85: // NDS server
      case 92: // Associated IP
      case 148: // DOTS Address
      case 150: // TFTP server address
      case 162: { // Encrypted DNS Server
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

      case 53: { // DHCP message type
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

      case 2: // Time offset
      case 24: // Path MTU aging timeout
      case 35: // ARP cache timeout
      case 38: // TCP keepalive interval
      case 51: // IP address leasetime
      case 58: // T1
      case 59: // T2
      case 91: // Client last transaction time
      case 108: // IPv6-Only preferred
      case 152: // base-time
      case 153: // start-time-of-state
      case 154: // query-start-time
      case 155: // query-end-time
      case 211: { // reboot-time
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

int
main(int argc, char **argv) {
  unsigned char buf[16 << 10];
  struct stat st;
  ssize_t nbytes;
  int rc, fd;

  if (argc < 2 || argv[0] == NULL || argv[1] == NULL) {
    fprintf(stderr, "Usage: $ leasedump /var/lib/dhcpcd/if-ssid.lease\n");
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

  if (!print_lease(buf, st.st_size)) {
    fprintf(stderr, "Could not parse %s\n", argv[1]);
    goto fail;
  }

  close(fd);

  return EXIT_SUCCESS;
fail:
  close(fd);
  return EXIT_FAILURE;
}
