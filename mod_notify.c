#include <switch.h>
#include <switch_types.h>
#include <switch_core.h>
#include <switch_curl.h>
#include <string.h>
#include <switch_version.h>

SWITCH_MODULE_LOAD_FUNCTION(mod_notify_load);
SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_notify_shutdown);
SWITCH_MODULE_DEFINITION(mod_notify, mod_notify_load, mod_notify_shutdown, NULL);

#define SWITCH_LESS_THAN(x, y)                               \
	(((FS_VERSION_MAJOR == x) && (FS_VERSION_MINOR == y)) || \
	 ((FS_VERSION_MAJOR == x) && (FS_VERSION_MINOR < y)) || (FS_VERSION_MAJOR < x))

enum notify_state
{
	MOD_NOTIFY_UNDEFINE,
	MOD_NOTIFY_SENT,
	MOD_NOTIFY_NOTSENT
};
struct response_event_data
{
	char uuid[SWITCH_UUID_FORMATTED_LENGTH + 1];
	enum notify_state state;
	switch_mutex_t *mutex;
};
typedef struct response_event_data response_t;

struct originate_register_data
{
	switch_memory_pool_t *pool;
	char *destination;
	char *realm;
	char *user;
	switch_mutex_t *mutex;
	uint32_t *timelimit;
	switch_bool_t wait_any_register;
};
typedef struct originate_register_data originate_register_t;

#define PUSH_NOTIFY_USAGE ""          \
						  "extension" \
						  ""
SWITCH_STANDARD_API(notify_api_function)
{
	stream->write_function(stream, "OK");
	return SWITCH_STATUS_SUCCESS;
}

static char *get_url_from_contact(char *buf)
{
	char *url = NULL, *e;

	switch_assert(buf);

	while (*buf == ' ')
	{
		buf++;
	}

	if (*buf == '"')
	{
		buf++;
		if ((e = strchr(buf, '"')))
		{
			buf = e + 1;
		}
	}

	while (*buf == ' ')
	{
		buf++;
	}

	url = strchr(buf, '<');

	if (url && (e = switch_find_end_paren(url, '<', '>')))
	{
		url++;
		url = strdup(url);
		e = strchr(url, '>');
		*e = '\0';
	}
	else
	{
		if (url)
			buf++;
		url = strdup(buf);
	}
	return url;
}

static void originate_register_event_handler(switch_event_t *event)
{
	char *dest = NULL;
	originate_register_t *originate_data = (struct originate_register_data *)event->bind_user_data;
	char *event_username = NULL, *event_realm = NULL, *event_call_id = NULL, *event_contact = NULL, *event_profile = NULL;
	char *destination = NULL;
	const char *update_reg = NULL, *domain_name = NULL, *dial_user = NULL;
	uint32_t timelimit_sec = 0;

	switch_memory_pool_t *pool;
	switch_mutex_t *handles_mutex;
	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "originate_register_event_handler fired!\n");

	if (!originate_data)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "originate_register_event_handler originate_data is null!\n");
		return;
	}

	pool = originate_data->pool;
	handles_mutex = originate_data->mutex;
	domain_name = originate_data->realm;
	dial_user = originate_data->user;

	update_reg = switch_event_get_header(event, "update-reg");
	if (!zstr(update_reg) && switch_true(update_reg))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "originate_register_event_handler user already registration, skip originate\n");
		return;
	}

	event_username = switch_event_get_header(event, "username");
	event_realm = switch_event_get_header(event, "realm");
	event_call_id = switch_event_get_header(event, "call-id");
	event_contact = switch_event_get_header(event, "contact");
	event_profile = switch_event_get_header(event, "profile-name");

	if (zstr(event_username) || zstr(event_realm) || zstr(event_call_id) || zstr(event_profile) || zstr(event_contact) || zstr(domain_name) || zstr(dial_user))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "CARUSTO. No parameter for originate call via sofia::register\n");
		return;
	}

	if (strcasecmp(event_realm, domain_name) || strcasecmp(event_username, dial_user))
	{
		return;
	}

	dest = get_url_from_contact(event_contact);

	if (zstr(dest))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "originate_register_event_handler No destination contact data string\n");
		goto end;
	}
	// switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "originate_register_event_handler domain_name: %s, dial_user: %s, event_username: %s, event_realm: %s, event_call_id: %s, event_contact: %s, event_profile: %s, dest: %s \n", domain_name, dial_user, event_username, event_realm, event_call_id, event_contact, event_profile, dest);

	timelimit_sec = *originate_data->timelimit;

	destination =
		switch_mprintf("[registration_token=%s,originate_timeout=%u]sofia/%s/%s:_:[originate_timeout=%u,enable_send_notify=false,notify_wait_any_register=%s]notify_wait/%s@%s",
					   event_call_id,
					   timelimit_sec,
					   event_profile,
					   dest,
					   timelimit_sec,
					   originate_data->wait_any_register == SWITCH_TRUE ? "true" : "false",
					   event_username,
					   event_realm);

	switch_mutex_lock(handles_mutex);
	originate_data->destination = switch_core_strdup(pool, destination);
	switch_mutex_unlock(handles_mutex);

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "originate_register_event_handler Try originate to '%s' (by registration event)\n", destination);

end:
	switch_safe_free(destination);
	switch_safe_free(dest);
}

static void response_event_handler(switch_event_t *event)
{
	char *uuid = NULL, *response = NULL;
	response_t *data = (response_t *)event->bind_user_data;

	uuid = switch_event_get_header(event, "uuid");
	if (zstr(uuid) || !data)
	{
		return;
	}

	if (strcmp(uuid, data->uuid) != 0)
	{
		return;
	}

	response = switch_event_get_header(event, "response");
	if (zstr(response))
	{
		return;
	}

	switch_mutex_lock(data->mutex);
	if (!strcasecmp(response, "sent"))
	{
		data->state = MOD_NOTIFY_SENT;
	}
	else
	{
		data->state = MOD_NOTIFY_NOTSENT;
	}
	switch_mutex_unlock(data->mutex);
}

/* fake user_wait */
switch_endpoint_interface_t *notify_wait_endpoint_interface;
static switch_call_cause_t push_wait_outgoing_channel(switch_core_session_t *session,
													  switch_event_t *var_event,
													  switch_caller_profile_t *outbound_profile,
													  switch_core_session_t **new_session, switch_memory_pool_t **pool, switch_originate_flag_t flags,
													  switch_call_cause_t *cancel_cause);

switch_io_routines_t push_wait_io_routines = {
	/*.outgoing_channel */ push_wait_outgoing_channel};

static switch_call_cause_t push_wait_outgoing_channel(switch_core_session_t *session,
													  switch_event_t *var_event,
													  switch_caller_profile_t *outbound_profile,
													  switch_core_session_t **new_session, switch_memory_pool_t **_pool, switch_originate_flag_t flags,
													  switch_call_cause_t *cancel_cause)
{
	switch_call_cause_t cause = SWITCH_CAUSE_NONE;
	char *cid_name_override = NULL, *cid_num_override = NULL;
	uint32_t timelimit_sec = 0;
	uint32_t current_timelimit = 0;
	switch_time_t start = 0;
	int diff = 0;
	switch_channel_t *channel = NULL;
	switch_memory_pool_t *pool = NULL;
	char *destination = NULL; //, *dialer_number = NULL;
	switch_bool_t wait_any_register = SWITCH_FALSE;
	char *user = NULL, *domain = NULL, *dup_domain = NULL;
	char *var_val = NULL;
	switch_event_t *event = NULL;
	switch_event_node_t *response_event = NULL, *register_event = NULL;
	response_t notify_response = {{
									  0,
								  },
								  MOD_NOTIFY_UNDEFINE,
								  NULL};
	originate_register_t originate_data = {
		0,
	};

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify push_wait_outgoing_channel fired!\n");

	if (var_event && !zstr(switch_event_get_header(var_event, "originate_reg_token")))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "Skip originate in case have custom originate token registration\n");
		return cause;
	}

	start = switch_epoch_time_now(NULL);
	switch_core_new_memory_pool(&pool);
	if (!pool)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify cannot create pool!\n");
		return cause;
	}
	if (session)
	{
		channel = switch_core_session_get_channel(session);
	}
	if (!outbound_profile || zstr(outbound_profile->destination_number))
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify not found outbound_profile or destination_number !\n");
		goto done;
	}

	user = switch_core_strdup(pool, outbound_profile->destination_number);
	if (!user)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify not found user !\n");
		goto done;
	}
	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify found user: %s!\n", user);
	if ((domain = strchr(user, '@')))
	{
		*domain++ = '\0';
	}
	else
	{
		domain = switch_core_get_domain(SWITCH_TRUE);
		dup_domain = domain;
	}

	if (!domain)
	{
		switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify not found domain !\n");
		goto done;
	}

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify found domain: %s!\n", domain);

	switch_uuid_str(notify_response.uuid, sizeof(notify_response.uuid));
	switch_mutex_init(&notify_response.mutex, SWITCH_MUTEX_NESTED, pool);

	if (var_event)
	{
		cid_name_override = switch_event_get_header(var_event, "origination_caller_id_name");
		cid_num_override = switch_event_get_header(var_event, "origination_caller_id_number");
		if ((var_val = switch_event_get_header(var_event, "originate_timeout")))
		{
			int tmp = (int)strtol(var_val, NULL, 10);
			if (tmp > 0)
			{
				timelimit_sec = (uint32_t)tmp;
			}
		}
	}

	if (timelimit_sec <= 0)
	{
		timelimit_sec = 10;
	}
	current_timelimit = timelimit_sec;

	originate_data.pool = pool;
	originate_data.realm = switch_core_strdup(pool, domain);
	originate_data.user = switch_core_strdup(pool, user);
	originate_data.destination = NULL;
	originate_data.mutex = NULL;
	originate_data.timelimit = 0;
	originate_data.wait_any_register = SWITCH_FALSE;

	switch_mutex_init(&originate_data.mutex, SWITCH_MUTEX_NESTED, pool);

	if (var_event && switch_true(switch_event_get_header(var_event, "notify_wait_any_register")))
	{
		wait_any_register = originate_data.wait_any_register = SWITCH_TRUE;
	}

	originate_data.timelimit = &current_timelimit;

	switch_event_bind_removable("notify_originate_register", SWITCH_EVENT_CUSTOM, "sofia::register", originate_register_event_handler, &originate_data, &register_event);

	if (wait_any_register == SWITCH_FALSE)
	{
		if ((switch_event_bind_removable(modname, SWITCH_EVENT_CUSTOM, "mobile::push::response", response_event_handler, &notify_response, &response_event) != SWITCH_STATUS_SUCCESS))
		{
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_WARNING, "Couldn't bind event!\n");
			goto done;
		}
	}

	// dialer_number = switch_event_get_header(event, "dialer_number");

	// if (zstr(dialer_number))
	// {
	// 	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify push_wait_outgoing_channel. dialer_number not found\n");
	// 	goto done;
	// }

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "mod_notify push_wait_outgoing_channel found dialer: %s!\n", dialer_number);

	/*Create event 'mobile::push::notification' for send push notification*/
	if (!var_event || (var_event && (!(var_val = switch_event_get_header(var_event, "enable_send_notify")) || zstr(var_val) || switch_true(var_val))))
	{
		if (switch_event_create_subclass(&event, SWITCH_EVENT_CUSTOM, "mobile::push::notification") == SWITCH_STATUS_SUCCESS)
		{
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "uuid", notify_response.uuid);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "type", "voip");
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "user", user);
			switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "realm", domain);
			// switch_event_add_header_string(event, SWITCH_STACK_BOTTOM, "dialer", dialer_number);
			// switch_event_add_body(event, "{\"content-available\":true,\"custom\":[{\"name\":\"content-message\",\"value\":\"incomming call\"}]}");
			switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_ERROR, "CARUSTO. Fire event APN for User: %s@%s\n", user, domain);
			switch_event_fire(&event);
			switch_event_destroy(&event);
		}
	}

	while (current_timelimit > 0)
	{
		diff = (int)(switch_epoch_time_now(NULL) - start);
		current_timelimit = timelimit_sec - diff;

		if (wait_any_register != SWITCH_TRUE)
		{
			switch_mutex_lock(notify_response.mutex);
			if (notify_response.state == MOD_NOTIFY_NOTSENT)
			{
				switch_mutex_unlock(notify_response.mutex);
				switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_DEBUG, "mod_notify push_wait_outgoing_channel. Event NOTIFY don't sent to %s@%s, so stop wait for incoming register\n", user, domain);
				break;
			}
			switch_mutex_unlock(notify_response.mutex);
		}

		if (session)
		{
			switch_ivr_parse_all_messages(session);
		}

		if (channel && !switch_channel_ready(channel))
		{
			break;
		}
		if (cancel_cause && *cancel_cause > 0)
		{
			break;
		}

		switch_mutex_lock(originate_data.mutex);
		if (!zstr(originate_data.destination))
		{
			destination = switch_core_strdup(pool, originate_data.destination);
		}
		switch_mutex_unlock(originate_data.mutex);

		if (!zstr(destination))
		{
			/*Unbind from 'sofia::register' event for current originate route*/
			if (register_event)
			{
				switch_event_unbind(&register_event);
				register_event = NULL;
			}
#if SWITCH_LESS_THAN(1, 8)
			if (switch_ivr_originate(session, new_session, &cause, destination, current_timelimit, NULL,
									 cid_name_override, cid_num_override, outbound_profile, var_event, flags,
									 cancel_cause) == SWITCH_STATUS_SUCCESS)
			{
#else
			if (switch_ivr_originate(session, new_session, &cause, destination, current_timelimit, NULL,
									 cid_name_override, cid_num_override, outbound_profile, var_event, flags,
									 cancel_cause, NULL) == SWITCH_STATUS_SUCCESS)
			{
#endif
				const char *context;
				switch_caller_profile_t *cp;
				switch_channel_t *new_channel = NULL;

				new_channel = switch_core_session_get_channel(*new_session);

				if ((context = switch_channel_get_variable(new_channel, "context")))
				{
					if ((cp = switch_channel_get_caller_profile(new_channel)))
					{
						cp->context = switch_core_strdup(cp->pool, context);
					}
				}
				switch_core_session_rwunlock(*new_session);
			}
			break;
		}

		switch_cond_next();
		switch_yield(1000);
	}
done:
	if (response_event)
	{
		switch_event_unbind(&response_event);
		response_event = NULL;
	}
	if (register_event)
	{
		switch_event_unbind(&register_event);
		register_event = NULL;
	}
	if (notify_response.mutex)
	{
		switch_mutex_destroy(notify_response.mutex);
	}
	switch_safe_free(dup_domain);
	if (pool)
	{
		switch_core_destroy_memory_pool(&pool);
	}
	return cause;
}

SWITCH_MODULE_LOAD_FUNCTION(mod_notify_load)
{
	switch_api_interface_t *api_interface;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s is loading ...\n", modname);
	/* connect my internal structure to the blank pointer passed to me */
	*module_interface = switch_loadable_module_create_module_interface(pool, modname);
	SWITCH_ADD_API(api_interface, "notify", "Notify Service", notify_api_function, PUSH_NOTIFY_USAGE);

	notify_wait_endpoint_interface = (switch_endpoint_interface_t *)switch_loadable_module_create_interface(*module_interface, SWITCH_ENDPOINT_INTERFACE);
	notify_wait_endpoint_interface->interface_name = "notify_wait";
	notify_wait_endpoint_interface->io_routines = &push_wait_io_routines;

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "%s loaded\n", modname);

	/* indicate that the module should continue to be loaded */
	return SWITCH_STATUS_SUCCESS;
}

SWITCH_MODULE_SHUTDOWN_FUNCTION(mod_notify_shutdown)
{
	return SWITCH_STATUS_SUCCESS;
}
