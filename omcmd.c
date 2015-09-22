/* omcmd.c - see COPYING for license
 *  (c)2004 David L. Parsley, parsley@linuxjedi.org
 */

#include <stdarg.h>
#include <stdlib.h>
#include <sys/time.h>
#include <sys/socket.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <string.h>

#include <omapip/result.h>
#include <dhcpctl/dhcpctl.h>

#include "omcmd.h"

void usage() {
    printf("Usage: omcmd [-k keyname secret | -K keyfile ] [-s server] [-v] \\\n");
    printf("  <command> <objtype> <args>\n");
    exit(-1);
}

void toobig(char *var,char *val) {
    printf("%s too long: %s longer than %d\n",var,val,MAXLEN);
    exit(-1);
}

void exitout(isc_result_t status) {
    if (status) fprintf(stderr, "Error: %s\n", isc_result_totext(status));
    exit(status);
}

int main (int argc, char **argv) {
    /* values for setting */
    dhcpctl_data_string values[16];
    /* value for getting */
    dhcpctl_data_string value=NULL;
    dhcpctl_handle authenticator=dhcpctl_null_handle;
    dhcpctl_handle object=dhcpctl_null_handle;
    dhcpctl_handle connection=dhcpctl_null_handle;
    isc_result_t status;
    const char *algorithm = "hmac-md5";
    char keyname[MAXLEN + 1];
    char secret[MAXLEN + 1];
    char secret_base64[MAXLEN + 1];
    char server[MAXLEN +1];
    char objstring[MAXLEN +1];
    omtype objtype;
    char valstring[MAXLEN +1];
    char **lookupprops;
    int lookups;
    char *defaulthostprops[]={"name","hardware-address","hardware-type",
	"dhcp-client-identifier","ip-address","known","group"};
    int defaulthostnumprops=7;
    char *defaultleaseprops[]={"state","ip-address","dhcp-client-identifier",
	"client-hostname","hardware-address","hardware-type","ends","tstp",
	"tsfp","cltt"};
    int defaultleasenumprops=10;
    char *defaultgroupprops[]={"name"};
    int defaultgroupnumprops=1;
    omprop proptype;
    int seclength=0;
    int argindex=1;
    int valindex=1;
    int i;
    int waitfor=0;
    int port=7911;
    int outputformat=OM_TERSE;
    int slen;
    omcmd command;
    FILE *keyfile;

    object=dhcpctl_null_handle;
    for (valindex=0; valindex<16; valindex++){
	memset(&values[valindex],0,sizeof values[valindex]);
    }
    valindex=0;
    strcpy(server,"127.0.0.1");

    // process options
    while(argindex < argc && argv[argindex][0]=='-'){
	if ((argv[argindex][1] == 0) || ( argv[argindex][2] != 0)) {
	    usage();
	}
	switch(argv[argindex][1]){
	    case 'k':
		if (strlen(argv[++argindex]) < MAXLEN)
		    strcpy(keyname,argv[argindex]);
		else toobig("keyname",argv[argindex]);
		if (strlen(argv[++argindex]) < MAXLEN){
		    seclength=from64tobits(secret,argv[argindex]);
		    if (seclength == -1){
			fprintf(stderr,"Invalid base64 string: %s\n",argv[argindex]);
			exit(-1);
		    }
		}
		else toobig("secret",argv[argindex]);
		argindex++;
		break;
	    case 'K':
		if ((keyfile=fopen(argv[++argindex],"r"))==NULL){
		    fprintf(stderr,"Unable to open key file %s for reading\n",
			argv[argindex]);
		    exit(-1);
		}
		if (fgets(keyname,MAXLEN,keyfile)==NULL){
		    fprintf(stderr,"Unable to read keyname from key file %s\n",
			argv[argindex]);
		    exit(-1);
		}
		slen=strlen(keyname);
		if (keyname[slen-1] != '\n'){
		    toobig("keyname",keyname);
		}
		keyname[slen-1]='\0';
		if (fgets(secret_base64,MAXLEN,keyfile)==NULL){
		    fprintf(stderr,"Unable to read secret from key file %s\n",
			argv[argindex]);
		    exit(-1);
		}
		slen=strlen(secret_base64);
		if (secret_base64[slen-1] != '\n'){
		    toobig("base64 encoded secret",secret_base64);
		}
		secret_base64[slen-1]='\0';
		seclength=from64tobits(secret,secret_base64);
		if (seclength == -1){
		    fprintf(stderr,"Invalid base64 string: %s\n",secret_base64);
		    exit(-1);
		}
		argindex++;
		break;
	    case 'p':
		port = atoi(argv[++argindex]);
		argindex++;
		break;
	    case 's':
		if (strlen(argv[++argindex]) < MAXLEN)
		    strcpy(server,argv[argindex]);
		else toobig("server",argv[argindex]);
		argindex++;
		break;
	    case 'v':
		    outputformat=OM_VERBOSE;
		    argindex++;
		    break;
	    default:
		usage();
	}
    }

    if (argindex>=argc){
	fprintf(stderr, "Missing <command>\n");
	usage();
    }
    if (!(command=stringtocmd(argv[argindex]))){
	fprintf(stderr, "Unknown command: %s\n", argv[argindex]);
	usage();
    }
    if (++argindex>=argc){
	fprintf(stderr, "Missing <objtype>\n");
	usage();
    }
    if (strlen(argv[argindex]) < MAXLEN)
	strcpy(objstring,argv[argindex]);
    else toobig("objtype",argv[argindex]);
    if (++argindex>=argc){
	fprintf(stderr, "Missing required arguments\n");
	usage();
    }
    objtype=stringtoobj(objstring);
    if (!objtype){
	fprintf(stderr, "Unknown or unsupported object type: %s\n",objstring);
	exit(-1);
    }

    /* Start dhcpctl stuff */
    status=dhcpctl_initialize();
    if (status != ISC_R_SUCCESS) {
	fprintf(stderr, "dhcpctl_initialize: %s\n",
	    isc_result_totext(status));
	exitout(status);
    }
    authenticator=dhcpctl_null_handle;
    if (seclength){
        status=dhcpctl_new_authenticator(&authenticator, keyname, algorithm,
	   secret, seclength);
	if (status != ISC_R_SUCCESS) {
	    fprintf(stderr,"dhcpctl_new_authenticator: %s\n",
		isc_result_totext(status));
	    exitout(status);
	}
    }
    connection = dhcpctl_null_handle;
    status = dhcpctl_connect(&connection,server,port,authenticator);
    if (status != ISC_R_SUCCESS) {
	fprintf(stderr,"dhcpctl_connect: %s\n",
	    isc_result_totext(status));
	exitout(status);
    }
    /* Get an object to work with */
    status=dhcpctl_new_object (&object, connection,objstring);
    if (status != ISC_R_SUCCESS) {
	fprintf(stderr,"dhcpctl_new_object: %s\n",
	    isc_result_totext(status));
	exitout(status);
    }
    /* There's always a first attribute=value */
    if (!setvalue(&object,&values[0],argv[argindex])){
	fprintf(stderr,"bad attribute spec: %s\n",argv[argindex]);
	usage();
    }
    switch(command){
	/* For these, we need to open the object first. */
	case oc_lookup:
	case oc_remove:
	case oc_modify:
	    status=dhcpctl_open_object (object, connection, 0);
	    if (status != ISC_R_SUCCESS) {
		fprintf(stderr,"dhcpctl_open_object: %s\n",
		    isc_result_totext(status));
		exitout(status);
	    }
	    dhcpctl_wait_for_completion (object, &status);
	    if (status != ISC_R_SUCCESS) {
		fprintf(stderr,"dhcpctl_wait_for_completion: %s\n",
		    isc_result_totext(status));
		exit (status);
	    }
    }
    if (command == oc_create || command == oc_modify){
	for(argindex++;argindex<argc;argindex++){
	    if (!setvalue(&object,&values[valindex],argv[argindex])){
	        fprintf(stderr,"bad attribute spec: %s\n",argv[argindex]);
		usage();
	    }
	    valindex++;
	}
    }
    switch(command){
	case oc_remove:
	    status=dhcpctl_object_remove(connection, object);
	    waitfor=1;
	    break;
	case oc_create:
	    status=dhcpctl_open_object(object, connection, DHCPCTL_CREATE |
		DHCPCTL_EXCL);
	    waitfor=1;
	    break;
	case oc_modify:
	    status=dhcpctl_object_update(connection, object);
	    waitfor=1;
	    break;
    }
    if (waitfor){
	if (status != ISC_R_SUCCESS) exitout(status);
	dhcpctl_wait_for_completion(object, &status);
	exitout(status);
    }
    /* command == oc_lookup for sure now, all others have exited */
    if (++argindex == argc){
	outputformat=OM_VERBOSE;
	switch(objtype){
	    case obj_host:
		lookupprops=defaulthostprops;
		lookups=defaulthostnumprops;
		break;
	    case obj_lease:
		lookupprops=defaultleaseprops;
		lookups=defaultleasenumprops;
        break;
        case obj_group:
        lookupprops=defaultgroupprops;
        lookups=defaultgroupnumprops;
		break;
	}	
    }
    else{
	lookupprops=&argv[argindex];
	lookups=(argc - argindex);
    }
    for (i=0; i<lookups; i++){
	proptype=stringtoprop(lookupprops[i]);
	if (!proptype){
	    if (outputformat == OM_VERBOSE) printf("%s=",lookupprops[i]);
	    printf("error: unknown or unsupported property type: %s\n",
		lookupprops[i]);
	}
	else{
	    status = dhcpctl_get_value(&value, object, lookupprops[i]);
	    if (status != ISC_R_SUCCESS){
		if (status == ISC_R_NOTFOUND){
		    /* in non-verbose, always one line per specified property */
		    if(outputformat!=OM_VERBOSE) printf("\n");
		}
		else{
		    if (outputformat == OM_VERBOSE) printf("%s=",lookupprops[i]);
		    printf("error: getting %s: %s\n",lookupprops[i],
			isc_result_totext(status));
		}
	    }
	    else {
		if (outputformat == OM_VERBOSE) printf("%s=",lookupprops[i]);
		if(valuetostring(&value, proptype, valstring, MAXLEN +1)==NULL)
		    printf("error: couldn't convert value of %s to a string.\n",
			lookupprops[i]);
		else
		    printf("%s\n",valstring);
	    }
	    dhcpctl_data_string_dereference(&value, MDL);
	}
    }
    exit(ISC_R_SUCCESS);
}
