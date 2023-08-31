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

#define PUSH_NOTIFY_USAGE ""          \
						  "extension" \
						  ""
SWITCH_STANDARD_API(notify_api_function)
{
	stream->write_function(stream, "OK");
	return SWITCH_STATUS_SUCCESS;
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
	uint32_t timelimit_sec = 5;
	uint32_t current_timelimit = 5;
	switch_time_t start = 0;
	int diff = 0;
	switch_channel_t *channel = NULL;
	char *destination = "1001@voice.metechvn.com";

	switch_log_printf(SWITCH_CHANNEL_LOG, SWITCH_LOG_INFO, "mod_notify push_wait_outgoing_channel fired!\n");
	start = switch_epoch_time_now(NULL);
	if (session)
	{
		channel = switch_core_session_get_channel(session);
	}
	while (current_timelimit > 0)
	{
		diff = (int)(switch_epoch_time_now(NULL) - start);
		current_timelimit = timelimit_sec - diff;
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
		switch_cond_next();
		switch_yield(1000);
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
