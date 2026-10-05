#ifndef PSA_H
#define PSA_H

#ifdef __cplusplus
extern "C" {
#endif

/*
 * Advisory password strength analyzer (psa-core C ABI).
 * Does not authorize account creation.
 *
 * Analyze* functions return heap UTF-8 JSON. Free with psa_string_free.
 * On failure they return NULL; call psa_last_error() for a message.
 *
 * options_json may be NULL or a JSON object with optional keys:
 *   user_agent, skip_breach, skip_model / no_model,
 *   hibp_offline / hibp_offline_path, timeout_ms
 */

char *psa_analyze_offline(const char *password, const char *options_json);
char *psa_analyze(const char *password, const char *options_json);
char *psa_check_pwned(const char *password, const char *options_json);
char *psa_model_info(void);
void psa_string_free(char *s);
const char *psa_last_error(void);

#ifdef __cplusplus
}
#endif

#endif /* PSA_H */
