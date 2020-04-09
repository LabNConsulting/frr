/* key-chain for authentication.
 * Copyright (C) 2000 Kunihiro Ishiguro
 *
 * This file is part of GNU Zebra.
 *
 * GNU Zebra is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published
 * by the Free Software Foundation; either version 2, or (at your
 * option) any later version.
 *
 * GNU Zebra is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; see the file COPYING; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301 USA
 */

#include <zebra.h>

#include "command.h"
#include "memory.h"
#include "linklist.h"
#include "keychain.h"
#include "keycrypt.h"

DEFINE_MTYPE_STATIC(LIB, KEY, "Key")
DEFINE_MTYPE_STATIC(LIB, KEYCHAIN, "Key chain")

DEFINE_QOBJ_TYPE(keychain)
DEFINE_QOBJ_TYPE(key)

/* Master list of key chain. */
static struct list *keychain_list;

static struct keychain *keychain_new(void)
{
	struct keychain *keychain;
	keychain = XCALLOC(MTYPE_KEYCHAIN, sizeof(struct keychain));
	QOBJ_REG(keychain, keychain);
	return keychain;
}

static void keychain_free(struct keychain *keychain)
{
	QOBJ_UNREG(keychain);
	XFREE(MTYPE_KEYCHAIN, keychain);
}

static struct key *key_new(void)
{
	struct key *key = XCALLOC(MTYPE_KEY, sizeof(struct key));
	QOBJ_REG(key, key);
	return key;
}

static void key_free(struct key *key)
{
	QOBJ_UNREG(key);
	XFREE(MTYPE_KEY, key);
}

struct keychain *keychain_lookup(const char *name)
{
	struct listnode *node;
	struct keychain *keychain;

	if (name == NULL)
		return NULL;

	for (ALL_LIST_ELEMENTS_RO(keychain_list, node, keychain)) {
		if (strcmp(keychain->name, name) == 0)
			return keychain;
	}
	return NULL;
}

static int key_cmp_func(void *arg1, void *arg2)
{
	const struct key *k1 = arg1;
	const struct key *k2 = arg2;

	if (k1->index > k2->index)
		return 1;
	if (k1->index < k2->index)
		return -1;
	return 0;
}

static void key_delete_func(struct key *key)
{
	if (key->string)
		free(key->string);
        XFREE(MTYPE_KEYCRYPT_CIPHER_B64, key->string_encrypted);
	key_free(key);
}

static struct keychain *keychain_get(const char *name)
{
	struct keychain *keychain;

	keychain = keychain_lookup(name);

	if (keychain)
		return keychain;

	keychain = keychain_new();
	keychain->name = XSTRDUP(MTYPE_KEYCHAIN, name);
	keychain->key = list_new();
	keychain->key->cmp = (int (*)(void *, void *))key_cmp_func;
	keychain->key->del = (void (*)(void *))key_delete_func;
	listnode_add(keychain_list, keychain);

	return keychain;
}

static void keychain_delete(struct keychain *keychain)
{
	XFREE(MTYPE_KEYCHAIN, keychain->name);

	list_delete(&keychain->key);
	listnode_delete(keychain_list, keychain);
	keychain_free(keychain);
}

static struct key *key_lookup(const struct keychain *keychain, uint32_t index)
{
	struct listnode *node;
	struct key *key;

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->index == index)
			return key;
	}
	return NULL;
}

struct key *key_lookup_for_accept(const struct keychain *keychain,
				  uint32_t index)
{
	struct listnode *node;
	struct key *key;
	time_t now;

	now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->index >= index) {
			if (key->accept.start == 0)
				return key;

			if (key->accept.start <= now)
				if (key->accept.end >= now
				    || key->accept.end == -1)
					return key;
		}
	}
	return NULL;
}

struct key *key_match_for_accept(const struct keychain *keychain,
				 const char *auth_str)
{
	struct listnode *node;
	struct key *key;
	time_t now;

	now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->accept.start == 0
		    || (key->accept.start <= now
			&& (key->accept.end >= now || key->accept.end == -1)))
			if (key->string && (strncmp(key->string, auth_str, 16) == 0))
				return key;
	}
	return NULL;
}

struct key *key_lookup_for_send(const struct keychain *keychain)
{
	struct listnode *node;
	struct key *key;
	time_t now;

	now = time(NULL);

	for (ALL_LIST_ELEMENTS_RO(keychain->key, node, key)) {
		if (key->send.start == 0)
			return key;

		if (key->send.start <= now)
			if (key->send.end >= now || key->send.end == -1)
				return key;
	}
	return NULL;
}

static struct key *key_get(const struct keychain *keychain, uint32_t index)
{
	struct key *key;

	key = key_lookup(keychain, index);

	if (key)
		return key;

	key = key_new();
	key->index = index;
	listnode_add_sort(keychain->key, key);

	return key;
}

static void key_delete(struct keychain *keychain, struct key *key)
{
	listnode_delete(keychain->key, key);

	XFREE(MTYPE_KEY, key->string);
        XFREE(MTYPE_KEYCRYPT_CIPHER_B64, key->string_encrypted);
	key_free(key);
}

DEFUN_NOSH (key_chain,
       key_chain_cmd,
       "key chain WORD",
       "Authentication key management\n"
       "Key-chain management\n"
       "Key-chain name\n")
{
	int idx_word = 2;
	struct keychain *keychain;

	keychain = keychain_get(argv[idx_word]->arg);
	VTY_PUSH_CONTEXT(KEYCHAIN_NODE, keychain);

	return CMD_SUCCESS;
}

DEFUN (no_key_chain,
       no_key_chain_cmd,
       "no key chain WORD",
       NO_STR
       "Authentication key management\n"
       "Key-chain management\n"
       "Key-chain name\n")
{
	int idx_word = 3;
	struct keychain *keychain;

	keychain = keychain_lookup(argv[idx_word]->arg);

	if (!keychain) {
		vty_out(vty, "Can't find keychain %s\n", argv[idx_word]->arg);
		return CMD_WARNING_CONFIG_FAILED;
	}

	keychain_delete(keychain);

	return CMD_SUCCESS;
}

DEFUN_NOSH (key,
       key_cmd,
       "key (0-2147483647)",
       "Configure a key\n"
       "Key identifier number\n")
{
	int idx_number = 1;
	VTY_DECLVAR_CONTEXT(keychain, keychain);
	struct key *key;
	uint32_t index;

	index = strtoul(argv[idx_number]->arg, NULL, 10);
	key = key_get(keychain, index);
	VTY_PUSH_CONTEXT_SUB(KEYCHAIN_KEY_NODE, key);

	return CMD_SUCCESS;
}

DEFUN (no_key,
       no_key_cmd,
       "no key (0-2147483647)",
       NO_STR
       "Delete a key\n"
       "Key identifier number\n")
{
	int idx_number = 2;
	VTY_DECLVAR_CONTEXT(keychain, keychain);
	struct key *key;
	uint32_t index;

	index = strtoul(argv[idx_number]->arg, NULL, 10);
	key = key_lookup(keychain, index);
	if (!key) {
		vty_out(vty, "Can't find key %d\n", index);
		return CMD_WARNING_CONFIG_FAILED;
	}

	key_delete(keychain, key);

	vty->node = KEYCHAIN_NODE;

	return CMD_SUCCESS;
}

#if 0 /* superseded by keycrypt_build_passwords() */
/*
 * Do crypto conversions and memory allocations as needed for peer passwords.
 *
 * Returns CMD_SUCCESS on success; Non-CMD_SUCCESS return values are
 * CLI error values
 *
 * Regardless of return value, caller must check string pointers as
 * they may have been allocated. Caller must free or otherwise deal
 * with dynamically-allocated *ppPlainText, *ppCryptText if any.
 */
static int
build_passwords(
    struct vty *vty,
    const char *password_in,	/* IN */
    bool is_encrypted,		/* IN */
    char **ppPlainText,		/* OUT MTYPE_KEY */
    char **ppCryptText)		/* OUT MTYPE_KEYCRYPT_CIPHER_B64 */
{
	*ppCryptText = NULL;
	char *password;

        if (is_encrypted) {
#ifdef KEYCRYPT_ENABLED
                if (keycrypt_decrypt(MTYPE_KEY,
                        password_in, strlen(password_in),
                        &password, NULL)) {
                        vty_out(vty, "Crypto error\n");
                        return CMD_WARNING_CONFIG_FAILED;
                }
#else
		vty_out(vty, "%s: keycrypt not supported in this build",
                     __func__);
		zlog_err("%s: keycrypt not supported in this build", __func__);
		return CMD_WARNING_CONFIG_FAILED;
#endif
        } else {
		password = XSTRDUP(MTYPE_KEY, password_in);
        }

#ifdef KEYCRYPT_ENABLED
	if (keycrypt_is_now_encrypting() || is_encrypted) {
		if (keycrypt_encrypt(password, strlen(password),
		    ppCryptText, NULL)) {
                        XFREE(MTYPE_KEY, password);
                        vty_out(vty, "Crypto error\n");
                        return CMD_WARNING_CONFIG_FAILED;
		}
        }
#endif

	*ppPlainText = password;

	return CMD_SUCCESS;
}
#endif

DEFUN (key_string,
       key_string_cmd,
       "key-string [101] LINE",
       "Set key string\n"
       "Encrypted key follows\n"
       "The key\n")
{
	int idx_line = 1;
        bool is_encrypted = false;
        char *passwdPlain;
        char *passwdCrypt;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

        if (argc == 3) {
                is_encrypted = true;
                idx_line = 2;
        }

        keycrypt_err_t krc;
        krc = keycrypt_build_passwords(argv[idx_line]->arg, is_encrypted,
            MTYPE_KEY, &passwdPlain, &passwdCrypt);

        /*
         * Free old encrypted password, if any. The way to transition
         * from an encrypted password to a cleartext password is to
         * turn off "service password-encryption" and then explicitly
         * set the password in cleartext.
         */
        XFREE(MTYPE_KEYCRYPT_CIPHER_B64, key->string_encrypted);
        key->string_encrypted = passwdCrypt; /* may be NULL */

        XFREE(MTYPE_KEY, key->string);
	key->string = passwdPlain;

        if (krc) {
            vty_out(vty, "Error: keycrypt: %s\n", keycrypt_strerror(krc));
            /*
             * this error code doesn't fully encompass the situation.
             * Configuration will have changed, due to design requirement
             * to conserve keys even if they can't be encrypted/decrypted.
             */
            return CMD_WARNING_CONFIG_FAILED;
        }

	return CMD_SUCCESS;
}

DEFUN (no_key_string,
       no_key_string_cmd,
       "no key-string [LINE]",
       NO_STR
       "Unset key string\n"
       "The key\n")
{
	VTY_DECLVAR_CONTEXT_SUB(key, key);

        XFREE(MTYPE_KEY, key->string);
        XFREE(MTYPE_KEYCRYPT_CIPHER_B64, key->string_encrypted);

	return CMD_SUCCESS;
}

/* Convert HH:MM:SS MON DAY YEAR to time_t value.  -1 is returned when
   given string is malformed. */
static time_t key_str2time(const char *time_str, const char *day_str,
			   const char *month_str, const char *year_str)
{
	int i = 0;
	char *colon;
	struct tm tm;
	time_t time;
	unsigned int sec, min, hour;
	unsigned int day, month, year;

	const char *month_name[] = {
		"January",  "February", "March",  "April",     "May",
		"June",     "July",     "August", "September", "October",
		"November", "December", NULL};

#define _GET_LONG_RANGE(V, STR, MMCOND)                                        \
	{                                                                      \
		unsigned long tmpl;                                            \
		char *endptr = NULL;                                           \
		tmpl = strtoul((STR), &endptr, 10);                            \
		if (*endptr != '\0' || tmpl == ULONG_MAX)                      \
			return -1;                                             \
		if (MMCOND)                                                    \
			return -1;                                             \
		(V) = tmpl;                                                    \
	}
#define GET_LONG_RANGE(V, STR, MIN, MAX)                                       \
	_GET_LONG_RANGE(V, STR, tmpl<(MIN) || tmpl>(MAX))
#define GET_LONG_RANGE0(V, STR, MAX) _GET_LONG_RANGE(V, STR, tmpl > (MAX))

	/* Check hour field of time_str. */
	colon = strchr(time_str, ':');
	if (colon == NULL)
		return -1;
	*colon = '\0';

	/* Hour must be between 0 and 23. */
	GET_LONG_RANGE0(hour, time_str, 23);

	/* Check min field of time_str. */
	time_str = colon + 1;
	colon = strchr(time_str, ':');
	if (*time_str == '\0' || colon == NULL)
		return -1;
	*colon = '\0';

	/* Min must be between 0 and 59. */
	GET_LONG_RANGE0(min, time_str, 59);

	/* Check sec field of time_str. */
	time_str = colon + 1;
	if (*time_str == '\0')
		return -1;

	/* Sec must be between 0 and 59. */
	GET_LONG_RANGE0(sec, time_str, 59);

	/* Check day_str.  Day must be <1-31>. */
	GET_LONG_RANGE(day, day_str, 1, 31);

	/* Check month_str.  Month must match month_name. */
	month = 0;
	if (strlen(month_str) >= 3)
		for (i = 0; month_name[i]; i++)
			if (strncmp(month_str, month_name[i], strlen(month_str))
			    == 0) {
				month = i;
				break;
			}
	if (!month_name[i])
		return -1;

	/* Check year_str.  Year must be <1993-2035>. */
	GET_LONG_RANGE(year, year_str, 1993, 2035);

	memset(&tm, 0, sizeof(struct tm));
	tm.tm_sec = sec;
	tm.tm_min = min;
	tm.tm_hour = hour;
	tm.tm_mon = month;
	tm.tm_mday = day;
	tm.tm_year = year - 1900;

	time = mktime(&tm);

	return time;
#undef GET_LONG_RANGE
}

static int key_lifetime_set(struct vty *vty, struct key_range *krange,
			    const char *stime_str, const char *sday_str,
			    const char *smonth_str, const char *syear_str,
			    const char *etime_str, const char *eday_str,
			    const char *emonth_str, const char *eyear_str)
{
	time_t time_start;
	time_t time_end;

	time_start = key_str2time(stime_str, sday_str, smonth_str, syear_str);
	if (time_start < 0) {
		vty_out(vty, "Malformed time value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	time_end = key_str2time(etime_str, eday_str, emonth_str, eyear_str);

	if (time_end < 0) {
		vty_out(vty, "Malformed time value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	if (time_end <= time_start) {
		vty_out(vty, "Expire time is not later than start time\n");
		return CMD_WARNING_CONFIG_FAILED;
	}

	krange->start = time_start;
	krange->end = time_end;

	return CMD_SUCCESS;
}

static int key_lifetime_duration_set(struct vty *vty, struct key_range *krange,
				     const char *stime_str,
				     const char *sday_str,
				     const char *smonth_str,
				     const char *syear_str,
				     const char *duration_str)
{
	time_t time_start;
	uint32_t duration;

	time_start = key_str2time(stime_str, sday_str, smonth_str, syear_str);
	if (time_start < 0) {
		vty_out(vty, "Malformed time value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	krange->start = time_start;

	duration = strtoul(duration_str, NULL, 10);
	krange->duration = 1;
	krange->end = time_start + duration;

	return CMD_SUCCESS;
}

static int key_lifetime_infinite_set(struct vty *vty, struct key_range *krange,
				     const char *stime_str,
				     const char *sday_str,
				     const char *smonth_str,
				     const char *syear_str)
{
	time_t time_start;

	time_start = key_str2time(stime_str, sday_str, smonth_str, syear_str);
	if (time_start < 0) {
		vty_out(vty, "Malformed time value\n");
		return CMD_WARNING_CONFIG_FAILED;
	}
	krange->start = time_start;

	krange->end = -1;

	return CMD_SUCCESS;
}

void
keychain_encryption_state_change(bool now_encrypting)
{
#ifdef KEYCRYPT_ENABLED
    struct keychain *keychain;
    struct key *key;
    struct listnode *node;
    struct listnode *knode;

    /*
     * change from encrypting to non-encrypting has no effect on
     * previously-encrypted protocol keys: they remain encrypted.
     */
    if (!now_encrypting)
        return;

    /*
     * Some deamons don't use the keychain. Detect this case and
     * skip.
     */
    if (!keychain_list)
        return;

    for (ALL_LIST_ELEMENTS_RO(keychain_list, node, keychain)) {
        for (ALL_LIST_ELEMENTS_RO(keychain->key, knode, key)) {
            if (key->string) {
                if (key->string_encrypted)
                    continue;
                if (keycrypt_encrypt(key->string, strlen(key->string),
                    &(key->string_encrypted), NULL)) {
                        zlog_err("%s: can't encrypt for keychain \"%s\", key \"%u\"",
                            __func__, keychain->name, key->index);
                }
            }
        }
    }
#endif
}

void
keychain_encryption_show_status(struct vty *vty, const char *indentstr)
{
    struct keychain *keychain;
    struct key *key;
    struct listnode *node;
    struct listnode *knode;

    uint keys = 0;
    uint keys_encrypted = 0;

    /*
     * Some deamons don't use the keychain. Detect this case and
     * skip printing anything.
     */
    if (!keychain_list)
        return;

    for (ALL_LIST_ELEMENTS_RO(keychain_list, node, keychain)) {
        for (ALL_LIST_ELEMENTS_RO(keychain->key, knode, key)) {
            if (key->string) {
		++keys;

                if (key->string_encrypted)
		    ++keys_encrypted;

            }
        }
    }

    vty_out(vty, "%sKeychain: keys: %u, encrypted: %u\n",
	indentstr, keys, keys_encrypted);
}

DEFUN (accept_lifetime_day_month_day_month,
       accept_lifetime_day_month_day_month_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (accept_lifetime_day_month_month_day,
       accept_lifetime_day_month_month_day_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (accept_lifetime_month_day_day_month,
       accept_lifetime_month_day_day_month_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (accept_lifetime_month_day_month_day,
       accept_lifetime_month_day_month_day_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (accept_lifetime_infinite_day_month,
       accept_lifetime_infinite_day_month_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) infinite",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_infinite_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg);
}

DEFUN (accept_lifetime_infinite_month_day,
       accept_lifetime_infinite_month_day_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) infinite",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_infinite_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg);
}

DEFUN (accept_lifetime_duration_day_month,
       accept_lifetime_duration_day_month_cmd,
       "accept-lifetime HH:MM:SS (1-31) MONTH (1993-2035) duration (1-2147483646)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_duration_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_number_3]->arg);
}

DEFUN (accept_lifetime_duration_month_day,
       accept_lifetime_duration_month_day_cmd,
       "accept-lifetime HH:MM:SS MONTH (1-31) (1993-2035) duration (1-2147483646)",
       "Set accept lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_duration_set(
		vty, &key->accept, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_number_3]->arg);
}

DEFUN (no_accept_lifetime,
       no_accept_lifetime_cmd,
       "no accept-lifetime",
       NO_STR
       "Unset accept-lifetime\n")
{
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	if (key->accept.start)
		key->accept.start = 0;
	if (key->accept.end)
		key->accept.end = 0;
	if (key->accept.duration)
		key->accept.duration = 0;

	return CMD_SUCCESS;
}

DEFUN (send_lifetime_day_month_day_month,
       send_lifetime_day_month_day_month_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (send_lifetime_day_month_month_day,
       send_lifetime_day_month_month_day_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (send_lifetime_month_day_day_month,
       send_lifetime_month_day_day_month_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS (1-31) MONTH (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Day of th month to expire\n"
       "Month of the year to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_number_3 = 6;
	int idx_month_2 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (send_lifetime_month_day_month_day,
       send_lifetime_month_day_month_day_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) HH:MM:SS MONTH (1-31) (1993-2035)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Time to expire\n"
       "Month of the year to expire\n"
       "Day of th month to expire\n"
       "Year to expire\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_hhmmss_2 = 5;
	int idx_month_2 = 6;
	int idx_number_3 = 7;
	int idx_number_4 = 8;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_hhmmss_2]->arg, argv[idx_number_3]->arg,
		argv[idx_month_2]->arg, argv[idx_number_4]->arg);
}

DEFUN (send_lifetime_infinite_day_month,
       send_lifetime_infinite_day_month_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) infinite",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_infinite_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg);
}

DEFUN (send_lifetime_infinite_month_day,
       send_lifetime_infinite_month_day_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) infinite",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Never expires\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_infinite_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg);
}

DEFUN (send_lifetime_duration_day_month,
       send_lifetime_duration_day_month_cmd,
       "send-lifetime HH:MM:SS (1-31) MONTH (1993-2035) duration (1-2147483646)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Day of th month to start\n"
       "Month of the year to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_number = 2;
	int idx_month = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_duration_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_number_3]->arg);
}

DEFUN (send_lifetime_duration_month_day,
       send_lifetime_duration_month_day_cmd,
       "send-lifetime HH:MM:SS MONTH (1-31) (1993-2035) duration (1-2147483646)",
       "Set send lifetime of the key\n"
       "Time to start\n"
       "Month of the year to start\n"
       "Day of th month to start\n"
       "Year to start\n"
       "Duration of the key\n"
       "Duration seconds\n")
{
	int idx_hhmmss = 1;
	int idx_month = 2;
	int idx_number = 3;
	int idx_number_2 = 4;
	int idx_number_3 = 6;
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	return key_lifetime_duration_set(
		vty, &key->send, argv[idx_hhmmss]->arg, argv[idx_number]->arg,
		argv[idx_month]->arg, argv[idx_number_2]->arg,
		argv[idx_number_3]->arg);
}

DEFUN (no_send_lifetime,
       no_send_lifetime_cmd,
       "no send-lifetime",
       NO_STR
       "Unset send-lifetime\n")
{
	VTY_DECLVAR_CONTEXT_SUB(key, key);

	if (key->send.start)
		key->send.start = 0;
	if (key->send.end)
		key->send.end = 0;
	if (key->send.duration)
		key->send.duration = 0;

	return CMD_SUCCESS;
}

static struct cmd_node keychain_node = {KEYCHAIN_NODE, "%s(config-keychain)# ",
					1};

static struct cmd_node keychain_key_node = {KEYCHAIN_KEY_NODE,
					    "%s(config-keychain-key)# ", 1};

static int keychain_strftime(char *buf, int bufsiz, time_t *time)
{
	struct tm tm;
	size_t len;

	localtime_r(time, &tm);

	len = strftime(buf, bufsiz, "%T %b %d %Y", &tm);

	return len;
}

static int keychain_config_write(struct vty *vty)
{
	struct keychain *keychain;
	struct key *key;
	struct listnode *node;
	struct listnode *knode;
	char buf[BUFSIZ];

	for (ALL_LIST_ELEMENTS_RO(keychain_list, node, keychain)) {
		vty_out(vty, "key chain %s\n", keychain->name);

		for (ALL_LIST_ELEMENTS_RO(keychain->key, knode, key)) {
			vty_out(vty, " key %d\n", key->index);

			if (key->string) {
                                if (key->string_encrypted) {
                                    if (!key->string) {
                                        vty_out(vty,
                                            "!!! Error: Unable to decrypt "
                                            "the following string\n");
                                    }
                                    vty_out(vty, "  key-string 101 %s\n",
                                        key->string_encrypted);
                                } else
                                    vty_out(vty, "  key-string %s\n",
                                        key->string);
                        }

			if (key->accept.start) {
				keychain_strftime(buf, BUFSIZ,
						  &key->accept.start);
				vty_out(vty, "  accept-lifetime %s", buf);

				if (key->accept.end == -1)
					vty_out(vty, " infinite");
				else if (key->accept.duration)
					vty_out(vty, " duration %ld",
						(long)(key->accept.end
						       - key->accept.start));
				else {
					keychain_strftime(buf, BUFSIZ,
							  &key->accept.end);
					vty_out(vty, " %s", buf);
				}
				vty_out(vty, "\n");
			}

			if (key->send.start) {
				keychain_strftime(buf, BUFSIZ,
						  &key->send.start);
				vty_out(vty, "  send-lifetime %s", buf);

				if (key->send.end == -1)
					vty_out(vty, " infinite");
				else if (key->send.duration)
					vty_out(vty, " duration %ld",
						(long)(key->send.end
						       - key->send.start));
				else {
					keychain_strftime(buf, BUFSIZ,
							  &key->send.end);
					vty_out(vty, " %s", buf);
				}
				vty_out(vty, "\n");
			}
		}
		vty_out(vty, "!\n");
	}

	return 0;
}

void keychain_init(void)
{
	keychain_list = list_new();

	install_node(&keychain_node, keychain_config_write);
	install_node(&keychain_key_node, NULL);

	install_default(KEYCHAIN_NODE);
	install_default(KEYCHAIN_KEY_NODE);

	install_element(CONFIG_NODE, &key_chain_cmd);
	install_element(CONFIG_NODE, &no_key_chain_cmd);
	install_element(KEYCHAIN_NODE, &key_cmd);
	install_element(KEYCHAIN_NODE, &no_key_cmd);

	install_element(KEYCHAIN_NODE, &key_chain_cmd);
	install_element(KEYCHAIN_NODE, &no_key_chain_cmd);

	install_element(KEYCHAIN_KEY_NODE, &key_string_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_key_string_cmd);

	install_element(KEYCHAIN_KEY_NODE, &key_chain_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_key_chain_cmd);

	install_element(KEYCHAIN_KEY_NODE, &key_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_key_cmd);

	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_day_month_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_day_month_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_month_day_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_month_day_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_infinite_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_infinite_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_duration_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&accept_lifetime_duration_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_accept_lifetime_cmd);

	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_day_month_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_day_month_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_month_day_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_month_day_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_infinite_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_infinite_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_duration_day_month_cmd);
	install_element(KEYCHAIN_KEY_NODE,
			&send_lifetime_duration_month_day_cmd);
	install_element(KEYCHAIN_KEY_NODE, &no_send_lifetime_cmd);
}
