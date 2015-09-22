/* omcmd.h - see COPYING for license.
 * (c)2004 David L. Parsley <parsley@linuxjedi.org>
 */
#include <stdarg.h>
#include <netinet/in.h>

#include <omapip/result.h>
#include <dhcpctl/dhcpctl.h>

/* Max. string length */
#define MAXLEN 255

/* output formats */
#define OM_TERSE 0
#define OM_VERBOSE 1

/* Command constants.
 * zero is error condition */
typedef enum {
    oc_notfound,
    oc_lookup,
    oc_create,
    oc_remove,
    oc_modify
} omcmd;

/* Object properties.
 * Note: all possible object properties aren't implemented. */
typedef enum {
    op_unknown,
    op_state,
    op_ipaddr,
    op_dhcp_client_id,
    op_client_hostname,
    op_hwaddr,
    op_hwtype,
    op_ends,
    op_tstp,
    op_tsfp,
    op_cltt,
    op_name,
    op_statements,
    op_known,
    op_group
} omprop;

/* Possible lease states. */
typedef enum {
    os_unknown,
    os_free,
    os_active,
    os_expired,
    os_released,
    os_abandoned,
    os_reset,
    os_backup,
    os_reserved,
    os_bootp
} omstate;

/* Object types. 
 * Note: not all types implemented. */
typedef enum {
    obj_unknown,
    obj_host,
    obj_lease,
    obj_group
} omtype;

int from64tobits(char*,const char*);
omcmd stringtocmd(char *cmdstring);
omprop stringtoprop(char *propstring);
omtype stringtoobj(char *objstring);
char *statetostring(omstate state);
int setvalue(dhcpctl_handle *object, dhcpctl_data_string *value, char *valspec);
char *valuetostring(dhcpctl_data_string *p_val, omprop proptype, char *buf, int bufsz);
