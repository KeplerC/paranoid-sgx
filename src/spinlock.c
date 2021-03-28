#include "sgx_spinlock.h"

static inline void _mm_pause(void) __attribute__((always_inline));
static inline int _InterlockedExchange(int volatile * dst, int val) __attribute__((always_inline));

static inline void _mm_pause(void)  /* definition requires -ffreestanding */
{
    __asm __volatile(
        "pause"
    );
}

static inline int _InterlockedExchange(int volatile * dst, int val)
{
    int res;

    __asm __volatile(
        "lock xchg %2, %1;"
        "mov %2, %0"
        : "=m" (res)
        : "m" (*dst),
        "r" (val) 
        : "memory"
    );

    return (res);
   
}

uint32_t sgx_spin_lock(sgx_spinlock_t *lock)
{
    while(_InterlockedExchange((volatile int *)lock, 1) != 0) {
        while (*lock) {
            /* tell cpu we are spinning */
            _mm_pause();
        } 
    }

    return (0);
}

uint32_t sgx_spin_unlock(sgx_spinlock_t *lock)
{
    *lock = 0;

    return (0);
}