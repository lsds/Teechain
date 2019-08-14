#ifndef _OCALLS_H_
#define _OCALLS_H_

#if defined(__cplusplus)
extern "C" {
#endif

void ocall_print(const char* msg);
void ocall_print_important(const char* msg);
void ocall_error(const char* msg);
void ocall_monotonic_counter_sleep();

#if defined(__cplusplus)
}
#endif


#endif /* !_OCALLS_H_ */
