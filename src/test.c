/*
  This program was contributed by Shane Watts
  [modifications by AGM]
  [more modifications by Kragen Sitaker]

  You need to add the following (or equivalent) to the /etc/pam.conf file.
  # check authorization
  check_user   auth       required     /usr/lib/security/pam_unix_auth.so
  check_user   account    required     /usr/lib/security/pam_unix_acct.so
 */

#include <security/pam_appl.h>
#include <security/pam_misc.h>
#include <stdio.h>

static struct pam_conv conv = {
    misc_conv,
    NULL
};

int main(int argc, char *argv[])
{
    pam_handle_t *pamh=NULL;
    int retval;
    const char *user="nobody";
    const char* pUsername = NULL;

    if(argc == 2) {
        user = argv[1];
    }

    if(argc > 2) {
        fprintf(stderr, "Usage: check_user [username]\n");
        exit(1);
    }

    retval = pam_start("test", user, &conv, &pamh);
        
    if (retval == PAM_SUCCESS)
        retval = pam_authenticate(pamh, 0);    /* is user really user? */

    if (retval == PAM_SUCCESS)
        retval = pam_acct_mgmt(pamh, 0);       /* permitted access? */

    /* This is where we have been authorized or not. */

    if (retval == PAM_SUCCESS) {
	pam_get_item(pamh, PAM_USER, (const void**)&pUsername);
        fprintf(stdout, "Authenticated %s\n", pUsername);
    } else {
        fprintf(stdout, "Not Authenticated: %s\n", pam_strerror(pamh, retval));
    }

    if (pam_end(pamh,retval) != PAM_SUCCESS) {     /* close Linux-PAM */
        pamh = NULL;
        fprintf(stderr, "check_user: failed to release authenticator\n");
        exit(1);
    }

    return ( retval == PAM_SUCCESS ? 0:1 );       /* indicate success */
}
