#define DEBUG 1
#define DUMP_SEND 1

#if DEBUG
#	define Debug(x) x
#else
#	define Debug(x)
#endif

#if DUMP_SEND
#	define DumpSend(x) x
#else
#	define DumpSend(x)
#endif

