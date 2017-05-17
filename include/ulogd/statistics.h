#include <stdio.h>
#include <stdlib.h>
#include <sys/time.h>
#include <ulogd/ulogd.h>

#define DEBUG_STATISTICS

#ifdef DEBUG_STATISTICS
#define TIME_ELAPSED(codeToTime) do{ \
    struct timeval beginTime, endTime; \
    gettimeofday(&beginTime, NULL); \
    {codeToTime;} \
    gettimeofday(&endTime, NULL); \
    long secTime  = endTime.tv_sec - beginTime.tv_sec; \
    long usecTime = endTime.tv_usec - beginTime.tv_usec; \
    ulogd_log(ULOGD_NOTICE, "[%s(%d)]Elapsed Time: SecTime = %lds, UsecTime = %ldus!\n", __FILE__, __LINE__, secTime, usecTime); \
}while(0)
#else
#define TIME_ELAPSED(codeToTime) do{ \
	codeToTime;
}while(0)
#endif


