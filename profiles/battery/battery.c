/*
 *
 *  BlueZ - Bluetooth protocol stack for Linux
 *
 *  Copyright (C) 2012  Instituto Nokia de Tecnologia - INdT
 *  Copyright (C) 2014  Google Inc.
 *  Copyright (C) 2017  Red Hat Inc.
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 */

#ifdef HAVE_CONFIG_H
#include <config.h>
#endif

#include <ctype.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>

#include <glib.h>

#include "gdbus/gdbus.h"

#include "lib/bluetooth.h"
#include "lib/hci.h"
#include "lib/sdp.h"
#include "lib/uuid.h"

#include "src/dbus-common.h"
#include "src/shared/util.h"
#include "src/shared/att.h"
#include "src/shared/queue.h"
#include "src/shared/gatt-db.h"
#include "src/shared/gatt-client.h"
#include "src/plugin.h"
#include "src/adapter.h"
#include "src/device.h"
#include "src/profile.h"
#include "src/service.h"
#include "src/log.h"
#include "attrib/att.h"

#define BATTERY_INTERFACE "org.bluez.Battery1"

#define BATT_UUID16 0x180f

enum {
	BATTERY_LEVEL,
	BATTERY_POWER_STATE
};

/* Generic Attribute/Access Service */
struct batt {
	char *path; /* D-Bus path of device */
	struct btd_device *device;
	struct gatt_db *db;
	struct bt_gatt_client *client;
	struct gatt_db_attribute *attr;

	unsigned int batt_level_cb_id;
	uint16_t batt_level_io_handle;

	unsigned int batt_power_state_cb_id;
	uint16_t batt_power_state_io_handle;

	bool present;
	bool rechargeable;
	guint16 percentage;
	const char *state;
	const char *battery_level;
};

static void batt_free(struct batt *batt)
{
	gatt_db_unref(batt->db);
	bt_gatt_client_unref(batt->client);
	btd_device_unref(batt->device);
	g_free(batt);
}

static void parse_battery_level(struct batt *batt,
				const uint8_t *value)
{
	uint8_t percentage;

	if (batt->present == false) {
		batt->present = true;
		g_dbus_emit_property_changed(btd_get_dbus_connection(), batt->path,
						BATTERY_INTERFACE, "Present");
	}

	percentage = value[0];
	if (batt->percentage != percentage) {
		batt->percentage = percentage;
		DBG("Battery Level updated: %d%%", percentage);
		g_dbus_emit_property_changed(btd_get_dbus_connection(), batt->path,
						BATTERY_INTERFACE, "Percentage");
	}
}

static void parse_battery_power_state(struct batt *batt,
					const uint8_t *value)
{
	guint8 batt_presence;
	guint8 discharge_state;
	guint8 charge_state;
	guint8 battery_level;
	bool present;
	bool rechargeable;
	const char *state;
	const char *battery_level_s;

	/* Values explained at:
	 * https://www.bluetooth.com/specifications/gatt/viewer?attributeXmlFile=org.bluetooth.characteristic.battery_power_state.xml */
	batt_presence = value[0] & 0b11;
	discharge_state = (value[0] >> 2) & 0b11;
	charge_state = (value[0] >> 4) & 0b11;
	battery_level = (value[0] >> 6) & 0b11;

	/* Transform the attribute values into something consumable by UPower
	 * The string values are a subset of upower's up-types.c */

	if (batt_presence == 3) {
		present = true;
	} else {
		present = false;
		rechargeable = false;
		state = "unknown";
		battery_level_s = "unknown";
		goto out;
	}

	rechargeable = !(charge_state == 1);

	if (discharge_state == 3)
		state = "discharging";
	else if (charge_state == 3)
		state = "charging";
	else
		state = "fully-charged";

	if (battery_level == 2)
		battery_level_s = "normal";
	else if (battery_level == 3)
		battery_level_s = "critical";
	else
		battery_level_s = "unknown";

out:
	if (present != batt->present) {
		batt->present = present;
		g_dbus_emit_property_changed(btd_get_dbus_connection(), batt->path,
						BATTERY_INTERFACE, "Present");
	}
	if (rechargeable != batt->rechargeable) {
		batt->rechargeable = rechargeable;
		g_dbus_emit_property_changed(btd_get_dbus_connection(), batt->path,
						BATTERY_INTERFACE, "Rechargeable");
	}
	if (g_strcmp0(state, batt->state) != 0) {
		batt->state = state;
		g_dbus_emit_property_changed(btd_get_dbus_connection(), batt->path,
						BATTERY_INTERFACE, "State");
	}
	if (g_strcmp0(battery_level_s, batt->battery_level) != 0) {
		batt->battery_level = battery_level_s;
		g_dbus_emit_property_changed(btd_get_dbus_connection(), batt->path,
						BATTERY_INTERFACE, "BatteryLevel");
	}

	DBG("Power State 0x%X computed to:", value[0]);
	DBG("present: %s rechargeable: %s state: %s battery_level: %s",
			present ? "true" : "false",
			rechargeable ? "true" : "false",
			state, battery_level_s);
}

static void batt_io_value_cb(uint16_t value_handle, const uint8_t *value,
                             uint16_t length, void *user_data)
{
	struct batt *batt = user_data;

	if (value_handle == batt->batt_level_io_handle) {
		parse_battery_level(batt, value);
	} else if (value_handle == batt->batt_power_state_io_handle) {
		parse_battery_power_state(batt, value);
	} else {
		g_assert_not_reached();
	}
}

static void batt_io_ccc_written_cb(uint16_t att_ecode, void *user_data)
{
	guint char_type = GPOINTER_TO_UINT(user_data);

	if (att_ecode != 0) {
		if (char_type == BATTERY_LEVEL) {
			error("Battery Level: notifications not enabled %s",
				att_ecode2str(att_ecode));
		} else if (char_type == BATTERY_POWER_STATE) {
			error("Battery Power State: notifications not enabled %s",
				att_ecode2str(att_ecode));
		} else {
			g_assert_not_reached();
		}
		return;
	}

	DBG("Battery Level: notification enabled");
}

static void read_initial_battery_power_state_cb(bool success,
							uint8_t att_ecode,
							const uint8_t *value,
							uint16_t length,
							void *user_data)
{
	struct batt *batt = user_data;

	if (!success) {
		DBG("Reading battery power state failed with ATT errror: %u",
								att_ecode);
		return;
	}

	if (!length)
		return;

	parse_battery_power_state(batt, value);

	/* request notify */
	batt->batt_power_state_cb_id =
		bt_gatt_client_register_notify(batt->client,
		                               batt->batt_power_state_io_handle,
		                               batt_io_ccc_written_cb,
		                               batt_io_value_cb,
		                               batt,
		                               GUINT_TO_POINTER(BATTERY_POWER_STATE));
}

static void read_initial_battery_level_cb(bool success,
						uint8_t att_ecode,
						const uint8_t *value,
						uint16_t length,
						void *user_data)
{
	struct batt *batt = user_data;

	if (!success) {
		DBG("Reading battery level failed with ATT errror: %u",
								att_ecode);
		return;
	}

	if (!length)
		return;

	parse_battery_level(batt, value);

	/* request notify */
	batt->batt_level_cb_id =
		bt_gatt_client_register_notify(batt->client,
		                               batt->batt_level_io_handle,
		                               batt_io_ccc_written_cb,
		                               batt_io_value_cb,
		                               batt,
		                               GUINT_TO_POINTER(BATTERY_LEVEL));
}

static void handle_battery_level(struct batt *batt, uint16_t value_handle)
{
	batt->batt_level_io_handle = value_handle;

	if (!bt_gatt_client_read_value(batt->client, batt->batt_level_io_handle,
						read_initial_battery_level_cb, batt, NULL))
		DBG("Failed to send request to read battery level");
}

static void handle_battery_power_state(struct batt *batt, uint16_t value_handle)
{
	batt->batt_power_state_io_handle = value_handle;

	if (!bt_gatt_client_read_value(batt->client, batt->batt_power_state_io_handle,
						read_initial_battery_power_state_cb, batt, NULL))
		DBG("Failed to send request to read battery power state");
}

static bool uuid_cmp(uint16_t u16, const bt_uuid_t *uuid)
{
	bt_uuid_t lhs;

	bt_uuid16_create(&lhs, u16);

	return bt_uuid_cmp(&lhs, uuid) == 0;
}

static void handle_characteristic(struct gatt_db_attribute *attr,
								void *user_data)
{
	struct batt *batt = user_data;
	uint16_t value_handle;
	bt_uuid_t uuid;

	if (!gatt_db_attribute_get_char_data(attr, NULL, &value_handle, NULL,
								NULL, &uuid)) {
		error("Failed to obtain characteristic data");
		return;
	}

	if (uuid_cmp(GATT_CHARAC_BATTERY_LEVEL, &uuid))
		handle_battery_level(batt, value_handle);
	else if (uuid_cmp(GATT_CHARAC_BATTERY_POWER_STATE, &uuid))
		handle_battery_power_state(batt, value_handle);
	else {
		char uuid_str[MAX_LEN_UUID_STR];

		bt_uuid_to_string(&uuid, uuid_str, sizeof(uuid_str));
		DBG("Unsupported characteristic: %s", uuid_str);
	}
}

static void handle_batt_service(struct batt *batt)
{
	gatt_db_service_foreach_char(batt->attr, handle_characteristic, batt);
}

static int batt_probe(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct batt *batt = btd_service_get_user_data(service);
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("BATT profile probe (%s)", addr);

	/* Ignore, if we were probed for this device already */
	if (batt) {
		error("Profile probed twice for the same device!");
		return -1;
	}

	batt = g_new0(struct batt, 1);
	if (!batt)
		return -1;

	batt->percentage = -1;
	batt->device = btd_device_ref(device);
	btd_service_set_user_data(service, batt);

	return 0;
}

static void batt_remove(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct batt *batt;
	char addr[18];

	ba2str(device_get_address(device), addr);
	DBG("BATT profile remove (%s)", addr);

	batt = btd_service_get_user_data(service);
	if (!batt) {
		error("BATT service not handled by profile");
		return;
	}

	batt_free(batt);
}

static void foreach_batt_service(struct gatt_db_attribute *attr, void *user_data)
{
	struct batt *batt = user_data;

	if (batt->attr) {
		error("More than one BATT service exists for this device");
		return;
	}

	batt->attr = attr;
	handle_batt_service(batt);
}

static void batt_reset(struct batt *batt)
{
	batt->attr = NULL;
	gatt_db_unref(batt->db);
	batt->db = NULL;
	bt_gatt_client_unregister_notify(batt->client, batt->batt_power_state_cb_id);
	bt_gatt_client_unregister_notify(batt->client, batt->batt_level_cb_id);
	bt_gatt_client_cancel_all(batt->client);
	bt_gatt_client_unref(batt->client);
	batt->client = NULL;
	if (batt->path) {
		g_dbus_unregister_interface(btd_get_dbus_connection(),
					    batt->path, BATTERY_INTERFACE);
		g_free(batt->path);
		batt->path = NULL;
	}
	btd_device_unref(batt->device);
}

static gboolean property_get_battery_level(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct batt *batt = data;
	const char *empty_str = "";

	if (!batt->battery_level)
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &empty_str);
	else
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &batt->battery_level);

	return TRUE;
}

static gboolean property_get_state(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct batt *batt = data;
	const char *empty_str = "";

	if (!batt->state)
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &empty_str);
	else
		dbus_message_iter_append_basic(iter, DBUS_TYPE_STRING, &batt->state);

	return TRUE;
}

static gboolean property_get_percentage(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct batt *batt = data;

	dbus_message_iter_append_basic(iter, DBUS_TYPE_UINT16, &batt->percentage);

	return TRUE;
}

static gboolean property_get_rechargeable(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct batt *batt = data;
	dbus_bool_t rechargeable;

	rechargeable = batt->rechargeable ? TRUE : FALSE;
	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &rechargeable);

	return TRUE;
}

static gboolean property_get_present(
					const GDBusPropertyTable *property,
					DBusMessageIter *iter, void *data)
{
	struct batt *batt = data;
	dbus_bool_t present;

	present = batt->present ? TRUE : FALSE;
	dbus_message_iter_append_basic(iter, DBUS_TYPE_BOOLEAN, &present);

	return TRUE;
}

static const GDBusPropertyTable battery_properties[] = {
	{ "Present", "b", property_get_present },
	{ "Rechargeable", "b", property_get_rechargeable },
	{ "Percentage", "q", property_get_percentage },
	{ "State", "s", property_get_state },
	{ "BatteryLevel", "s", property_get_battery_level },
	{ }
};

static int batt_accept(struct btd_service *service)
{
	struct btd_device *device = btd_service_get_device(service);
	struct gatt_db *db = btd_device_get_gatt_db(device);
	struct bt_gatt_client *client = btd_device_get_gatt_client(device);
	struct batt *batt = btd_service_get_user_data(service);
	char addr[18];
	bt_uuid_t batt_uuid;

	ba2str(device_get_address(device), addr);
	DBG("BATT profile accept (%s)", addr);

	if (!batt) {
		error("BATT service not handled by profile");
		return -1;
	}

	batt->db = gatt_db_ref(db);
	batt->client = bt_gatt_client_clone(client);

	/* Handle the BATT services */
	bt_uuid16_create(&batt_uuid, BATT_UUID16);
	gatt_db_foreach_service(db, &batt_uuid, foreach_batt_service, batt);

	if (!batt->attr) {
		error("BATT attribute not found");
		batt_reset(batt);
		return -1;
	}

	batt->path = g_strdup (device_get_path(device));

	if (g_dbus_register_interface(btd_get_dbus_connection(),
					batt->path, BATTERY_INTERFACE,
					NULL, NULL,
					battery_properties, batt,
					NULL) == FALSE) {
		error("Unable to register %s interface for %s",
			BATTERY_INTERFACE, batt->path);
		batt_reset(batt);
		return -EINVAL;
	}

	btd_service_connecting_complete(service, 0);

	return 0;
}

static int batt_disconnect(struct btd_service *service)
{
	struct batt *batt = btd_service_get_user_data(service);

	batt_reset(batt);

	btd_service_disconnecting_complete(service, 0);

	return 0;
}

static struct btd_profile batt_profile = {
	.name		= "batt-profile",
	.remote_uuid	= BATTERY_UUID,
	.device_probe	= batt_probe,
	.device_remove	= batt_remove,
	.accept		= batt_accept,
	.disconnect	= batt_disconnect,
};

static int batt_init(void)
{
	return btd_profile_register(&batt_profile);
}

static void batt_exit(void)
{
	btd_profile_unregister(&batt_profile);
}

BLUETOOTH_PLUGIN_DEFINE(battery, VERSION, BLUETOOTH_PLUGIN_PRIORITY_DEFAULT,
							batt_init, batt_exit)
