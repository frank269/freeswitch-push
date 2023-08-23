include $(top_srcdir)/build/modmake.rulesam
MODNAME=mod_notify

mod_LTLIBRARIES     = mod_notify.la
mod_notify_la_SOURCES  = mod_notify.c

mod_notify_la_CFLAGS   = $(AM_CFLAGS)
mod_notify_la_CFLAGS   += -DFS_VERSION_MAJOR=$(SWITCH_VERSION_MAJOR)
mod_notify_la_CFLAGS   += -DFS_VERSION_MINOR=$(SWITCH_VERSION_MINOR)
mod_notify_la_LIBADD   = $(switch_builddir)/libfreeswitch.la
mod_notify_la_LDFLAGS  = -avoid-version -module -no-undefined -shared
