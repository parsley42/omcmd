/* omfuncs - functions that would just clutter up omcmd.c ;-)
 * see COPYING for license.
 * (c)2004 David L. Parsley <parsley@linuxjedi.org>
 */

#include <time.h>
#include <string.h>
#include <stdarg.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>

#include <omapip/result.h>
#include <dhcpctl/dhcpctl.h>

#include "omcmd.h"

const char *commandstrings[]={
    "lookup",
    "find",
    "create",
    "add",
    "new",
    "remove",
    "delete",
    "modify",
    "update",
    "change",
    "list",
    ""
};
const int commandnum[]={
	1,
	1,
	2,
	2,
	2,
	3,
	3,
	4,
	4,
	4,
	5
};
const char *propstrings[]={
    "state",
    "ip-address",
    "dhcp-client-identifier",
    "client-hostname",
    "hardware-address",
    "hardware-type",
    "ends",
    "tstp",
    "tsfp",
    "cltt",
    "name",
    "statements",
    "known",
    "group"
};
#define OM_NUMPROPS 14
const char *objectstrings[]={
    "host",
    "lease",
    "group"
};
#define OM_NUMOBJTYPES 3
const char *statestrings[]={
    "free",
    "active",
    "expired",
    "released",
    "abandoned",
    "reset",
    "backup",
    "reserved",
    "bootp"
};
#define OM_NUMSTATES 9

omcmd stringtocmd(char *cmdstring){
    int i;
//    for (i=0; i<OM_NUMCOMMANDS; i++)
    for (i=0; commandstrings[i][0] != '\0'; i++)
	if (!strcmp(commandstrings[i],cmdstring)) return((omcmd)commandnum[i]);
    return(oc_notfound); // error
}

omprop stringtoprop(char *propstring){
    int i;
    for (i=0; i<OM_NUMPROPS; i++)
	if (!strcmp(propstrings[i],propstring)) return((omprop)(i+1));
    return(op_unknown);
}

omtype stringtoobj(char *objstring){
    int i;
    for (i=0; i<OM_NUMOBJTYPES; i++)
	if (!strcmp(objectstrings[i],objstring)) return((omtype)(i+1));
    return(obj_unknown);
}

omstate stringtostate(char *statestring){
    int i;
    for (i=0; i<OM_NUMSTATES; i++)
	if (!strcmp(statestrings[i],statestring)) return((omstate)(i+1));
    return(os_unknown);
}

char *statetostring(omstate state){
    if (state>0 && state<OM_NUMSTATES + 1) return((char *)statestrings[state-1]);
    return "unknown";
}

/* valspec is a string of form "var=value" 
 * Return values:
     0 - parse error
    -1 - error setting value
     1 - OK
*/
int setvalue(dhcpctl_handle *p_obj, dhcpctl_data_string *p_val, char *valspec){
    char *var, *val;
    isc_result_t status;
    dhcpctl_handle object;
    dhcpctl_data_string value;
    omprop setproperty;
    omstate setstate;
    struct in_addr convaddr;
    char hwaddr[6];
    int i;
    uint32_t hostint,netint;
    struct tm timestruct;
    time_t timeval;

    object=*p_obj;
    value=*p_val;
    var=valspec;
    val=index(valspec,'=');
    if (val == NULL) return 0;
    *val++='\0';
    setproperty=stringtoprop(var);
    switch(setproperty){
    case op_ipaddr:
	if (inet_pton(AF_INET, val, &convaddr)<=0) return 0;
	omapi_data_string_new(&value, 4, MDL);
	memcpy(value->value, &convaddr.s_addr,4);
	break;
    case op_hwaddr:
	if (strlen(val) != 17) return 0;
	for (i=0; i < 17; i+=3){
	    if (i != 15 && val[i+2] != ':') return 0;
	    val[i+2]='\0';
	    hwaddr[i/3]=(char)strtol(&val[i], NULL, 16);
	}
	omapi_data_string_new(&value, 6, MDL);
	memcpy(value->value, hwaddr, 6);
	break;
    case op_hwtype:
	hostint=atol(val);
	netint=htonl(hostint);
	omapi_data_string_new(&value, sizeof netint, MDL);
	memcpy(value->value, &netint, sizeof netint);
	break;
    case op_state:
	setstate=stringtostate(val);
	netint=htonl((unsigned long)setstate);
	omapi_data_string_new(&value, sizeof netint, MDL);
	memcpy(value->value, &netint, sizeof netint);
	break;
    case op_ends:
    case op_tstp:
    case op_tsfp:
    case op_cltt:
	strptime(val, "%a %b %d %T %Y", &timestruct);
	timeval=mktime(&timestruct);
	omapi_data_string_new(&value, 4, MDL);
	memcpy(value->value, &timeval, 4);
	break;
    case op_name:
    case op_client_hostname:
    case op_statements:
    case op_group:
	i=strlen(val);
	omapi_data_string_new(&value, i, MDL);
	memcpy(value->value, val, i);
	break;
    default:
	return 0;
    } /* end of switch */

    status=dhcpctl_set_value(object, value, var);
    if (status != ISC_R_SUCCESS){
	dhcpctl_data_string_dereference(&value, MDL);
	return -1;
    }
    return 1;
}

/* Return values:
     NULL - error converting value to string
     "string" - converted string
*/
char *valuetostring(dhcpctl_data_string *p_val, omprop proptype, char *buf, int bufsz){
    dhcpctl_data_string value;
    int i,j;
    time_t thetime;
    struct in_addr convaddr;
    char *statestring;
    uint32_t hostint,netint;

    value=*p_val;
    switch(proptype){
    case op_ends:
    case op_tstp:
    case op_tsfp:
    case op_cltt:
	memcpy(&thetime, value->value, value->len);
	ctime_r(&thetime,buf);
	buf[strlen(buf)-1]='\0';
	break;
    case op_ipaddr:
	memcpy(&convaddr.s_addr,value->value,4);
	if((void *)inet_ntop(AF_INET,&convaddr,buf,MAXLEN + 1)==NULL){
	    return NULL;
	}
	break;
    case op_client_hostname:
    case op_name:
	if(value->len > (bufsz-1)) return "error: name too long";
	memcpy(buf,value->value,value->len);
	buf[value->len]='\0';
	break;
    case op_statements:
 	if(value->len > (bufsz-1)) return "error: statement too long";
	memcpy(buf,value->value,value->len);
	buf[value->len]='\0';
    case op_dhcp_client_id:
    case op_hwaddr:
	if((value->len)*3 > (bufsz)) return "error: value too long";
	for(i=0,j=0;i<(value->len)-1;i++,j+=3){
	    sprintf(&buf[j],"%2.2x:",value->value[i]);
	}
	sprintf(&buf[j],"%2.2x",value->value[i]);
	break;
    case op_hwtype:
	memcpy(&netint,value->value,4);
	hostint=ntohl(netint);
	sprintf(buf,"%d",hostint);
	break;
    case op_state:
	memcpy(&netint,value->value,4);
	hostint=ntohl(netint);
	statestring=statetostring((omstate)hostint);
	strncpy(buf, statestring, bufsz);
	break;
    default:
	return NULL;
    }
    return buf;
}
