#include "devices/timer.h"
#include <debug.h>
#include <inttypes.h>
#include <round.h>
#include <stdio.h>
#include "threads/interrupt.h"
#include "threads/io.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include <stdlib.h>

/* See [8254] for hardware details of the 8254 timer chip. */

#if TIMER_FREQ < 19
#error 8254 timer requires TIMER_FREQ >= 19
#endif
#if TIMER_FREQ > 1000
#error TIMER_FREQ <= 1000 recommended
#endif

/* Number of timer ticks since OS booted. */
static int64_t ticks;

/* Number of loops per timer tick.
   Initialized by timer_calibrate(). */
static unsigned loops_per_tick;

static intr_handler_func timer_interrupt;
static bool too_many_loops (unsigned loops);
static void busy_wait (int64_t loops);
static void real_time_sleep (int64_t num, int32_t denom);

/* Sets up the 8254 Programmable Interval Timer (PIT) to
   interrupt PIT_FREQ times per second, and registers the
   corresponding interrupt. */
void
timer_init (void) {
	/* 8254 input frequency divided by TIMER_FREQ, rounded to
	   nearest. */
	uint16_t count = (1193180 + TIMER_FREQ / 2) / TIMER_FREQ;

	outb (0x43, 0x34);    /* CW: counter 0, LSB then MSB, mode 2, binary. */
	outb (0x40, count & 0xff);
	outb (0x40, count >> 8);

	intr_register_ext (0x20, timer_interrupt, "8254 Timer");
}

/* Calibrates loops_per_tick, used to implement brief delays. */
void
timer_calibrate (void) {
	unsigned high_bit, test_bit;

	ASSERT (intr_get_level () == INTR_ON);
	printf ("Calibrating timer...  ");

	/* Approximate loops_per_tick as the largest power-of-two
	   still less than one timer tick. */
	loops_per_tick = 1u << 10;
	while (!too_many_loops (loops_per_tick << 1)) {
		loops_per_tick <<= 1;
		ASSERT (loops_per_tick != 0);
	}

	/* Refine the next 8 bits of loops_per_tick. */
	high_bit = loops_per_tick;
	for (test_bit = high_bit >> 1; test_bit != high_bit >> 10; test_bit >>= 1)
		if (!too_many_loops (high_bit | test_bit))
			loops_per_tick |= test_bit;

	printf ("%'"PRIu64" loops/s.\n", (uint64_t) loops_per_tick * TIMER_FREQ);
}

/* Returns the number of timer ticks since the OS booted. */
int64_t
timer_ticks (void) {
	enum intr_level old_level = intr_disable ();
	int64_t t = ticks;
	intr_set_level (old_level);
	barrier ();
	return t;
}

/* Returns the number of timer ticks elapsed since THEN, which
   should be a value once returned by timer_ticks(). */
int64_t
timer_elapsed (int64_t then) {
	return timer_ticks () - then;
}

/* PROJECT 1 - Alarm Clock */
/* Suspends execution for approximately TICKS timer ticks. */
void
timer_sleep (int64_t ticks) {
	int64_t start = timer_ticks ();
    
    // 아래의 while문에서, sema_down()을 실행하기 위해서는 현재 INTR_ON 상태여야하냐? 몰루겠다
    // ASSERT(intr_get_level() == INTR_ON);

    // 아직 ticks만큼 시간이 흐르지 않았다면, sema_down()을 호출한다.

    // 현재 쓰레드를 쓰레드 A라고 하자,

    // sema_down()은 쓰레드 A를 sleep_sema의 waiters에 넣고,
    // 쓰레드 A의 상태를 RUNNING에서 BLOCKED로 변경한 뒤,
    // ready_list에서 pop_left한 하나의 쓰레드 'next'를 thread_launch()의 인자로 전달하여 실행시키며
    // thread_launch()는 쓰레드 A에서 쓰레드 'next'로 context switching 을 실시한다.
    // 그래서 쓰레드 A는 sema_down() 함수 내부의 thread_block(); 라인에서 완전히 멈춰있다. (사실 더 내부의 thread_launch에서 멈춰있겠지만, 거기는 지금 이야기 하고자 하는 맥락에서는 의미 없는 실행 단위이다.)
    // 그리고 이 모든 과정은 [interrupt의 비활성화 - 활성화 블록] 안에서 일어나기 때문에 원자성이 유지된다.

    // 쓰레드 A에서 sema_down()이 return될 수 있는 상황은, 다른 쓰레드가 sema_up()을 실행할때 이다.
    // sema_up()은 sleep_sema의 waiters에서 하나의 thread를 pop_left하여 이를 ready_list에 넣어준다.
    // 이때 ready_list에 들어간 thread가 쓰레드 A라면 
    // 쓰레드 A의 status는 BLOCKED에서 READY로 바뀌었을것이고,
    // 다음 context-switching이 일어날 때 running하기 위해 ready_list에서 pop_left해서 나온 쓰레드가 쓰레드 A라면,
    // 쓰레드 A가 실행될 것이다.

    // 쓰레드 A는 block되기 직전에 thread_block(); 라인에 멈춰있었으므로, thread_block(); 라인 부터 실행될 것이고,
    // 이때, 운좋게도 sema->value가 1이라면(현재 공유 자원을 사용하고 있는 쓰레드가 하나도 없다면)
    // sema->value를 1 감소시켜 공유자원이 사용되고 있다는 사실을 모든 쓰레드들이 확인 할 수 있게 갱신한다. (내가 공유자원을 쓰고있다! 하하)
    // 마찬가지로 이 모든 과정은 [interrupt의 비활성화 - 활성화 블록] 안에서 진행된다.
    // 그리고 마지막에 interrupt를 활성화 한 뒤 sema_down()이 return 된다.

    // sema_down()이 return 되었다면, 다시 while 조건문 에서 ticks 만큼의 시간이 흘렀는지 확인할 것이다.
    thread_current ()->wakeup_ticks = start + ticks;
    while(timer_elapsed (start) < ticks) {
        sema_down(get_sleep_list());
    }
}

/* Suspends execution for approximately MS milliseconds. */
void
timer_msleep (int64_t ms) {
	real_time_sleep (ms, 1000);
}

/* Suspends execution for approximately US microseconds. */
void
timer_usleep (int64_t us) {
	real_time_sleep (us, 1000 * 1000);
}

/* Suspends execution for approximately NS nanoseconds. */
void
timer_nsleep (int64_t ns) {
	real_time_sleep (ns, 1000 * 1000 * 1000);
}

/* Prints timer statistics. */
void
timer_print_stats (void) {
	printf ("Timer: %"PRId64" ticks\n", timer_ticks ());
}

/* Timer interrupt handler. */
static void
timer_interrupt (struct intr_frame *args UNUSED) {
	ticks++;
	thread_tick ();
    thread_wakeup(get_sleep_list(), ticks);
}

/* Returns true if LOOPS iterations waits for more than one timer
   tick, otherwise false. */
static bool
too_many_loops (unsigned loops) {
	/* Wait for a timer tick. */
	int64_t start = ticks;
	while (ticks == start)
		barrier ();

	/* Run LOOPS loops. */
	start = ticks;
	busy_wait (loops);

	/* If the tick count changed, we iterated too long. */
	barrier ();
	return start != ticks;
}

/* Iterates through a simple loop LOOPS times, for implementing
   brief delays.

   Marked NO_INLINE because code alignment can significantly
   affect timings, so that if this function was inlined
   differently in different places the results would be difficult
   to predict. */
static void NO_INLINE
busy_wait (int64_t loops) {
	while (loops-- > 0)
		barrier ();
}

/* Sleep for approximately NUM/DENOM seconds. */
static void
real_time_sleep (int64_t num, int32_t denom) {
	/* Convert NUM/DENOM seconds into timer ticks, rounding down.

	   (NUM / DENOM) s
	   ---------------------- = NUM * TIMER_FREQ / DENOM ticks.
	   1 s / TIMER_FREQ ticks
	   */
	int64_t ticks = num * TIMER_FREQ / denom;

	ASSERT (intr_get_level () == INTR_ON);
	if (ticks > 0) {
		/* We're waiting for at least one full timer tick.  Use
		   timer_sleep() because it will yield the CPU to other
		   processes. */
		timer_sleep (ticks);
	} else {
		/* Otherwise, use a busy-wait loop for more accurate
		   sub-tick timing.  We scale the numerator and denominator
		   down by 1000 to avoid the possibility of overflow. */
		ASSERT (denom % 1000 == 0);
		busy_wait (loops_per_tick * num / 1000 * TIMER_FREQ / (denom / 1000));
	}
}
