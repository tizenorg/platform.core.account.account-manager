SET(DAEMON account-svcd)

INCLUDE(FindPkgConfig)
pkg_check_modules(pkgs REQUIRED
		dlog
		db-util
		glib-2.0
		capi-base-common
		pkgmgr-info
		aul
		dbus-1
		gio-2.0
		gio-unix-2.0
		cynara-client
		cynara-session
		accounts-svc
)

FOREACH(flag ${pkgs_CFLAGS})
	SET(EXTRA_CFLAGS "${EXTRA_CFLAGS} ${flag}")
ENDFOREACH(flag)

SET(SERVER_SRCS
	account-server.c
	account-server-db.c
)

ADD_CUSTOM_COMMAND(
	WORKING_DIRECTORY
	OUTPUT account-mgr-stub.c
	COMMAND gdbus-codegen --interface-prefix org.tizen.
	--generate-c-code account-mgr-stub ../account_mgr.xml
	COMMENT "Generating Account SVC GDBus .c/.h")

SET(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${EXTRA_CFLAGS} -Wall -Werror")
SET(CMAKE_LDFLAGS "-Wl,-zdefs")

ADD_EXECUTABLE(${DAEMON} ${SERVER_SRCS} account-mgr-stub.c)

TARGET_LINK_LIBRARIES(${DAEMON} ${pkgs_LDFLAGS})

INSTALL(TARGETS ${DAEMON} DESTINATION bin)

