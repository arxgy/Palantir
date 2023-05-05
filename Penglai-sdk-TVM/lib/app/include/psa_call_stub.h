#include <stddef.h>
#include <stdint.h>
typedef struct psa_call_stub_t
{
    int32_t type;
    size_t in_vec_offset;
    size_t in_len;
    size_t out_vec_offset;
    size_t out_len;
}psa_call_stub_t;

typedef struct psa_call_arg_t
{
    int32_t type;
    void *in_vec;
    size_t in_len;
    void *out_vec;
    size_t out_len;
}psa_call_arg_t;