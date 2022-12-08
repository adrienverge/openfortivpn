#include "log.h"
#include "config.h"
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/wait.h>

#include <gtk/gtk.h>
#include <sys/stat.h>
#include <sys/mman.h>
#include <webkit2/webkit2.h>

// Global variables that need to be shared with the child process.
char *svpncookie = NULL;
size_t svpncookie_size = 0;

static void destroy_window_cb(GtkWidget *widget, GtkWidget *window)
{
	gtk_main_quit();
}

static gboolean close_web_view_cb(WebKitWebView *webView, GtkWidget *window)
{
	gtk_widget_destroy(window);
	return TRUE;
}

static void cookie_ready_callback(GObject *obj, GAsyncResult *res,
				  gpointer user_data)
{
	WebKitCookieManager *cookie_mgr = (WebKitCookieManager *)obj;

	GError *err = NULL;
	GList *cookies =
		webkit_cookie_manager_get_cookies_finish(cookie_mgr, res, &err);

	if (err != NULL) {
		printf("There was an error while getting the cookies: %s\n",
		       err->message);
		return;
	}

	// There was no cookie for the specified domain.
	if (!cookies)
		return;

	GList *cur = cookies;
	bool found_cookie = false;

	while (cur) {
		if (strcmp(soup_cookie_get_name(cur->data), "SVPNCOOKIE") ==
		    0) {
			strcpy(svpncookie, "SVPNCOOKIE=");

			strncpy(svpncookie +
					sizeof(char) * strlen("SVPNCOOKIE="),
				soup_cookie_get_value(cur->data),
				svpncookie_size);

			// Just in case that strncpy doesn't set the null terminator.
			svpncookie[svpncookie_size - 1] = '\0';
			found_cookie = true;
			break;
		}

		cur = cur->next;
	}

	g_list_free(cookies);

	// Exit the browser and gtk when we got the cookie.
	if (found_cookie)
		gtk_main_quit();
}

static void cookie_changed_cb(WebKitCookieManager *self, gpointer *data)
{
	char url[strlen("https://") + strlen((const char *)data) + 1];
	sprintf(url, "https://%s", (char *)data);

	webkit_cookie_manager_get_cookies(self, url, NULL,
					  cookie_ready_callback, data);
}

/* Returns the given directory/file under the home directory.
 * Return value must be manyally freed */
static char *get_under_home_dir(char *dir)
{
	char *username = getlogin();
	char *result =
		malloc(strlen("/home//") + strlen(username) + strlen(dir) + 1);

	sprintf(result, "/home/%s/%s", username, dir);

	return result;
}

static int webkit_get_cookie(char *gateway_host, uint16_t gateway_port,
		             char *realm, char *website_cert)
{
	char *cookie_file = get_under_home_dir(".openfortivpncookies");

	gtk_init(0, NULL);
	GtkWidget *main_window = gtk_window_new(GTK_WINDOW_TOPLEVEL);
	gtk_window_set_default_size(GTK_WINDOW(main_window), 800, 600);

	WebKitWebsiteDataManager *data_mgr =
		webkit_website_data_manager_new(NULL);

	WebKitCookieManager *cookie_mgr =
		webkit_website_data_manager_get_cookie_manager(data_mgr);

	webkit_cookie_manager_set_persistent_storage(
		cookie_mgr, cookie_file, WEBKIT_COOKIE_PERSISTENT_STORAGE_TEXT);

	WebKitWebContext *web_context =
		webkit_web_context_new_with_website_data_manager(data_mgr);
	WebKitWebView *web_view =
		WEBKIT_WEB_VIEW(webkit_web_view_new_with_context(web_context));

	gtk_container_add(GTK_CONTAINER(main_window), GTK_WIDGET(web_view));
	g_signal_connect(main_window, "destroy", G_CALLBACK(destroy_window_cb),
			 NULL);
	g_signal_connect(web_view, "close", G_CALLBACK(close_web_view_cb),
			 main_window);
	g_signal_connect(cookie_mgr, "changed", G_CALLBACK(cookie_changed_cb),
			 gateway_host);

	GTlsCertificate *cert =
		g_tls_certificate_new_from_pem(website_cert, -1, NULL);

	webkit_web_context_allow_tls_certificate_for_host(web_context, cert,
							  gateway_host);

	// Maximum possible port length is 5 (65536/XXXXX)
	char saml_url[strlen("https://XXXXX/remote/saml/start") + strlen(gateway_host) +
		      strlen("?realm=") + strlen(realm) + 1];

	if (realm) {
		sprintf(saml_url, "https://%s:%d/remote/saml/start?realm=%s", gateway_host,
			gateway_port, realm);
	} else {
		sprintf(saml_url, "https://%s:%d/remote/saml/start", gateway_host, gateway_port);
	}

	webkit_web_view_load_uri(web_view, saml_url);

	gtk_widget_grab_focus(GTK_WIDGET(web_view));
	gtk_widget_show_all(main_window);

	gtk_main();

	// Don't allow other users to read the cookies.
	chmod(cookie_file, 0600);

	free(cookie_file);
	return 0;
}

/* Returns 0 if the cookie was set successfully. -1 if there was an error. */
int saml_get_cookie(char *gateway_host, uint16_t gateway_port, char *realm,
		    char **dst_cookie, char *cert)
{
	svpncookie_size = sizeof(char) * (COOKIE_SIZE + 1);

	// This is needed because the browser (child process) needs to set the
	// cookie (write to the memory) which is not possible with malloc, etc.
	svpncookie = mmap(NULL, svpncookie_size, PROT_READ | PROT_WRITE,
			  MAP_SHARED | MAP_ANONYMOUS, -1, 0);

	char *user_id = getenv("SUDO_UID");

	if (!user_id) {
		log_error(
			"Could not find the SUDO_UID enviroment variable."
			"Please set it to your UID if you're not running with sudo (required to run the browser)\n");

		goto exit_error;
	}

	uid_t browser_uid = atoi(user_id);

	if (browser_uid == 0) {
		log_error(
			"Cannot run the browser as root. Please set SUDO_UID to an appropiate user.\n");
		goto exit_error;
	}

	if (fork() == 0) {
		char *home_dir = get_under_home_dir("");
		char *xdg_runtime_dir = malloc(strlen("/run/user/XXXXXXXXXX") + 1);
		sprintf(xdg_runtime_dir, "/run/user/%d", browser_uid);

		clearenv();
		setenv("HOME", home_dir, 1);
		setenv("DISPLAY", ":0", 1);

		// Needed for wayland
		setenv("XDG_RUNTIME_DIR", xdg_runtime_dir, 1);

		setuid(browser_uid);
		webkit_get_cookie(gateway_host, gateway_port, realm, cert);

		free(home_dir);
		free(xdg_runtime_dir);
		exit(EXIT_SUCCESS);
	}

	wait(NULL);

	*dst_cookie = strndup(svpncookie, COOKIE_SIZE);

	int ret = 0;
	goto exit;
exit_error:
	ret = -1;
	goto exit;
exit:
	munmap(svpncookie, svpncookie_size);
	return ret;
}
