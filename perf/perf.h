/*
 * Copyright (C) 2013 by Gregor Pintar <grpintar@gmail.com>
 *
 * Permission to use, copy, modify, and/or distribute this software for any
 * purpose with or without fee is hereby granted.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
 * ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
 * OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#ifndef PERF_ITERATIONS
#define PERF_ITERATIONS 1000000
#endif

#include <stdio.h>

#if defined(PERF_UNIX)

#include <unistd.h>
#include <sched.h>
#include <time.h>

#elif defined(PERF_WINDOWS)

#include <windows.h>
#include <PowrProf.h>
#include <ntstatus.h>

#endif

#if (defined(__GNUC__) || defined(__clang__)) && (defined(__i386__) || defined(__x86_64__))
#define PERF_RDTSC
#endif

#if defined(PERF_WINDOWS) || defined(PERF_RDTSC)

#include <stdint.h>

typedef uint64_t perf_int;
#define PERF_INT_MAX UINT64_MAX

#else

#include <time.h>

typedef clock_t perf_int;
#define PERF_INT_MAX (clock_t)UINT64_MAX

#endif

static inline perf_int perf_clock(void)
{
	#if defined(PERF_WINDOWS) && defined(PERF_QPC)

	LARGE_INTEGER x;

	QueryPerformanceCounter(&x);

	return x.QuadPart;

	#elif defined(PERF_RDTSC)

	uint32_t hi;
	uint32_t lo;

	__asm__ __volatile__
	(
		"cpuid\n"
		"rdtsc"
		: "=a"(lo), "=d"(hi)
		: "a"(0)
		: "%ebx", "%ecx"
	);

	return (((uint64_t)hi) << 32) | lo;

	#elif defined(_POSIX_CPUTIME)

	struct timespec x;

	if(clock_gettime(CLOCK_PROCESS_CPUTIME_ID, &x))
		perror("clock_gettime()");

	return (((uint64_t)x.tv_sec) << 32) | x.tv_nsec;

	#else

	return clock();

	#endif
}

#if defined(PERF_AVG)

#define PERF_START							\
{									\
	cycles = perf_clock();						\
	for(unsigned int perf_i = 0; perf_i < PERF_ITERATIONS; perf_i++)\
	{

#define PERF_STOP						\
	}							\
	cycles = (perf_clock() - cycles) / PERF_ITERATIONS;	\
}

#else

#define PERF_START							\
{									\
	perf_int t0;							\
	perf_int t1;							\
	cycles = PERF_INT_MAX;						\
	for(unsigned int perf_i = 0; perf_i < PERF_ITERATIONS; perf_i++)\
	{								\
		t0 = perf_clock();

#define PERF_STOP					\
		t1 = perf_clock() - t0 - perf_c;	\
		if(cycles > t1) cycles = t1;		\
	}										\
}

#endif

perf_int perf_c;

static void perf_init(void)
{
	perf_int cycles;

	#if defined(PERF_UNIX)

	struct sched_param p;

	#ifdef _GNU_SOURCE
	cpu_set_t set;

	/* lock process to one core */
	CPU_ZERO(&set);
	CPU_SET(0, &set);
	if(sched_setaffinity(0, CPU_ALLOC_SIZE(1), &set))
		perror("sched_setaffinity()");
	#endif

	puts("For better results disable dynamic CPU frequency scaling!");

	/* set highest possible priority */
	for(p.sched_priority = sched_get_priority_max(SCHED_FIFO);
		p.sched_priority; p.sched_priority--)
	{
		if(!sched_setscheduler(0, SCHED_FIFO, &p)) break;
	}
	printf("SCHED_FIFO with priority: %u\n", p.sched_priority);

	#elif defined(PERF_WINDOWS)

	SYSTEM_POWER_CAPABILITIES s;

	/* disable dynamic CPU frequency scaling */
	if(CallNtPowerInformation(SystemPowerCapabilities, 0, 0, &s, sizeof(s)) == STATUS_SUCCESS)
	{
		if(s.ProcessorMinThrottle != 100 || s.ProcessorMaxThrottle != 100)
		{
			s.ProcessorMinThrottle = 100;
			s.ProcessorMaxThrottle = 100;
			if(CallNtPowerInformation(SystemPowerCapabilities, &s, sizeof(s), 0, 0) != STATUS_SUCCESS)
				puts("Can't disable dynamic CPU frequency scaling!");
		}
	}
	else puts("Can't disable dynamic CPU frequency scaling!");

	/* set priority */
	if(!SetPriorityClass(GetCurrentProcess(), REALTIME_PRIORITY_CLASS))
		puts("SetPriorityClass() failed!");

	/* lock process to one core */
	if(!SetProcessAffinityMask(GetCurrentProcess(), 1))
		puts("SetProcessAffinityMask() failed!");

	#endif

	/* calibrate */
	perf_c = 0;
	PERF_START
	PERF_STOP
	perf_c = cycles;
}

void perf_rest(void)
{
	#if defined(PERF_UNIX)
	(void)sleep(1);
	#elif defined(PERF_WINDOWS)
	(void)Sleep(1);
	#endif
}
