#include <list>
#include <vector>
#include <deque>
#include <ctime>
#include <map>
#include <iostream>
#include <fstream>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/sysinfo.h>
#include <assert.h>
#include <string.h>
#include <unistd.h>

#include "pin.H"

#ifndef HOST_NAME_MAX
	#define HOST_NAME_MAX 64
#endif

#ifdef OLD_PIN
	#define PIN_InitLock InitLock
	#define PIN_GetLock GetLock
	#define PIN_ReleaseLock ReleaseLock
#endif

#define ASSERT_ENABLE

#if !defined(MAX_THREADS) || MAX_THREADS==0
	#if defined(__ia64)
		#define MAX_THREADS 8
		#define MAX_ELEMENTS_BITS 21
	#else
		#define MAX_THREADS 64
	#endif
#endif

#ifndef CACHE_LINE_SIZE
	#if defined(__ia64)
		#define CACHE_LINE_SIZE 128
	#else
		#define CACHE_LINE_SIZE 64
	#endif
#endif

using namespace std;

// *****************************************************

static UINT64 hash_fail = 0;

static struct timeval timer_start, timer_end;

static UINT32 numThreads = 0;
static UINT64 startTsc = 0;

static PIN_LOCK init_lock;

static int numa_nodes = 4;

static const char envname_page_size[] = "PIN_PAGE_SIZE_BYTES";
static const char envname_numa_nodes[] = "PIN_NUMA_NODES";

char addr_fname[1024];
char stat_fname[1024];

// *****************************************************

inline UINT64 getTSC()
{
	uint64_t r;
#if defined(__i386) || defined(__x86_64__)
	uint32_t lo, hi;
	__asm__ __volatile__ ("rdtsc" : "=a" (lo), "=d" (hi));
	r = ((uint64_t)hi << 32) | lo;
#elif defined(__ia64)
	__asm__ __volatile__ ("mov %0=ar.itc" : "=r" (r) :: "memory");
#else
	#error Architecture does not support high resolution counter
#endif
	return r;
}

struct pte_thread_t {
	UINT64 naccess;
};

static uint64_t npages = 0;
static uint32_t page_size = 4096;

static uint32_t page_size_bits;
static UINT64 page_mask;

#define GOLDEN_RATIO_PRIME_32 0x9e370001UL

static inline UINT32 hash_32(UINT32 val, unsigned int bits)
{
	/* On some cpus multiply is faster, on others gcc will do shifts */
	UINT32 hash = val * GOLDEN_RATIO_PRIME_32;

	/* High bits are more random, so use them. */
	return hash >> (32 - bits);
}

struct pte_t {
	UINT64 vaddr;
	long long int ts;
	pte_thread_t thread[MAX_THREADS];
	
	pte_t() {
		int i;
		
		this->vaddr = 0;
		
		for (i=0; i<MAX_THREADS; i++) {
			this->thread[i].naccess = 0;
		}
	}
};

long long int unix_timestamp()  
{
    time_t t = std::time(0);
    long long int now = static_cast<long long int> (t);
    return now;
}

static int get_n_bits(UINT64 v)
{
	int i;
	int bits = -1;
	UINT64 mask;
	
	for (i=0; i<64; i++) {
		mask = 1 << i;
		if (v & mask) {
			bits = i;
			assert(!(v & ~mask));
			break;
		}
	}
	
	assert(bits != -1);
	
	return bits;
}

static UINT64 get_highest_power2 (UINT64 max)
{
	UINT64 r = 1;
	
	while (r < max) {
		r <<= 1;
	}
	
	if (r > 1)
		r >>= 1;
	
	return r;
}

class page_table_t
{
	private:
		pte_t *storage;
		PIN_LOCK lock;
		int page_table_size_bits;
		int page_table_sets_bits;
		size_t size;

	public:
		page_table_t() {
			UINT64 max_el;
			struct sysinfo info;
			
			if (sysinfo(&info)) {
				cout << "sysinfo error" << endl;
				exit(1);
			}
			
			cout << "sizeof(size_t) " << sizeof(size_t) << endl;
			cout << "sizeof(pte_t) " << sizeof(pte_t) << endl;
			
			cout << "System memory: " << (info.totalram / (1024*1024)) << "MB" << endl;
			cout << "Free memory: " << (info.freeram / (1024*1024)) << "MB" << endl;
			
			max_el = ((info.totalram * 8) / 10) / sizeof(pte_t); // target using 70% of available RAM
			max_el = get_highest_power2(max_el);
			
			cout << "max_el: " << max_el << endl;
			
			if (max_el >= 4)
				page_table_sets_bits = 2;
			else
				page_table_sets_bits = 0;
			
		#if defined(__ia64)
			page_table_size_bits = MAX_ELEMENTS_BITS;
		#else
			page_table_size_bits = get_n_bits(max_el) - page_table_sets_bits;
		#endif
			
			cout << "page_table_size_bits: " << page_table_size_bits << endl;
			cout << "page_table_sets_bits: " << page_table_sets_bits << endl;
			
			size = 1 << (page_table_size_bits+page_table_sets_bits);
			
			cout << "Trying to allocate " << size << " elements using " << ((size*sizeof(pte_t)) / (1024*1024)) << "MB" << endl;
			
			this->storage = new pte_t[ size ];
			
			cout << "Memory allocated" << endl;
			PIN_InitLock(&this->lock);
		}
		
		inline size_t get_size () {
			return this->size;
		}
		
		inline pte_t* get_vector () {
			return this->storage;
		}

		static int compare (const void *a_, const void *b_) {
			pte_t *a = (pte_t*)a_;
			pte_t *b = (pte_t*)b_;
			
			// if (a->vaddr == 0) {
			// 	if (b->vaddr == 0)
			// 		return 0;
			// 	else
			// 		return 1;
			// }
			// else {
			// 	if (b->vaddr == 0)
			// 		return -1;
			// 	else {
			// 		if (a->vaddr < b->vaddr)
			// 			return -1;
			// 		else if (a->vaddr > b->vaddr)
			// 			return 1;
			// 		else
			// 			return 0;
			// 	}
			// }
			
			if ( *(long long int *)a->ts <  *(long long int*)b->ts ) return -1;
			if ( *(long long int*)a->ts == *(long long int*)b->ts ) return 0;
			if ( *(long long int*)a->ts >  *(long long int*)b->ts ) return 1;
		}
		
		void sort () {
			qsort(this->storage, size, sizeof(pte_t), &page_table_t::compare);
		}
		
		int valid (UINT64 i) {
			return (i < this->size && this->storage[i].vaddr != 0);
		}
		
		pte_t* fetch (UINT64 page_addr, int tid) {
			UINT32 hash, pos, i;
			INT64 free;
			pte_t *pte;
			
			hash = hash_32(page_addr >> page_size_bits, page_table_size_bits);
			pos = hash << page_table_sets_bits;
			
			free = 0;
			for (i=pos; i<pos+(1<<page_table_sets_bits); i++) {
				if (this->storage[i].vaddr == page_addr)
					return &(this->storage[i]);
				free += (this->storage[i].vaddr == 0);
			}
			
			if (!free)    // no free space in the set
				return NULL;
			
			// page never accessed before?
			
			if (tid == -1)
				return NULL;
			
			PIN_GetLock(&this->lock, 1);
			
			// check again in case of a race condition
			
			free = -1;
			for (i=pos; i<pos+(1<<page_table_sets_bits); i++) {
				if (this->storage[i].vaddr == page_addr) {
					PIN_ReleaseLock(&this->lock);
					return &(this->storage[i]);
				}
				if (this->storage[i].vaddr == 0 && free == -1)
					free = i;
			}
			
			if (free == -1)
				pte = NULL;
			else {
				pte = &(this->storage[free]);
				pte->vaddr = page_addr;
				pte->ts = unix_timestamp();
				npages++;
			}
			
			PIN_ReleaseLock(&this->lock);
			
			return pte;
		}
};

static page_table_t page_table;

// *****************************************************
#define PRINT_STATS(stats) \
	cout << stats; \
	stats_file << stats;

static void print_pgtb ()
{
	UINT64 i, j, naccesses = 0;
	pte_t *pte;
	ofstream file;
	
	file.open(addr_fname);
	
	file << "id,";
	file << "pgaddr,";
	for (j=0; j<numThreads; j++)
		file << "t" << j << ",";
	file << "accesses";

	file << endl;
	
	for (i=0, pte=page_table.get_vector(); page_table.valid(i); i++, pte++) {
		file << i << ",";
		file << pte->vaddr << ",";
		
		for (j=0; j<numThreads; j++){
			file << pte->thread[j].naccess << ",";
			naccesses += pte->thread[j].naccess;
		}
		file << naccesses;

		file << endl;
	}
	
	file.close();
}

static double calc_diff (struct timeval *start, struct timeval *end)
{
	return (end->tv_sec - start->tv_sec + (end->tv_usec - start->tv_usec) / 1000000.0);
}

VOID Fini(INT32 code, VOID *v)
{
	double diff_time;
	ofstream stats_file;
	static struct timeval sort_time_stamp;
	
	gettimeofday(&timer_end, NULL);
	diff_time = calc_diff(&timer_start, &timer_end);
	
	cout << "sorting page table..." << endl;
	page_table.sort();
	gettimeofday(&sort_time_stamp, NULL);
	cout << "sorting took " << calc_diff(&timer_end, &sort_time_stamp) << " seconds" << endl;
	
	cout << "total threads " << numThreads << endl << endl;

	// calculate statistics
	
	stats_file.open(stat_fname);

	PRINT_STATS( "Number of threads: " << numThreads << endl )
//	PRINT_STATS( "TLB number of entries: " << tlb_n_entries << endl )
//	PRINT_STATS( "TLB assoc: " << tlb_assoc << endl )
	PRINT_STATS( "Hash fail: " << hash_fail << endl)
	PRINT_STATS( "Page size: " << page_size << endl)
	PRINT_STATS( "Number of Pages: " << npages << endl )
	PRINT_STATS( "Amounf of memory: " << ((npages * page_size) / 1024) << "kb" << endl )
//	PRINT_STATS( "Memory accesses: " << mem_accesses_ac << endl )
//	PRINT_STATS( "TLB misses: " << tlb_misses_ac << endl )
//	PRINT_STATS( "TLB miss rate: " << (100.0 * ((double)tlb_misses_ac / (double)mem_accesses_ac)) << '%' << endl )
//	PRINT_STATS( "TLB evicts: " << n_tlb_evicts << endl )
//	PRINT_STATS( "TLB evict rate: " << (100.0 * ((double)n_tlb_evicts / (double)mem_accesses_ac)) << '%' << endl )
//	PRINT_STATS( "Memory accesses per TLB eviction: " << ((double)mem_accesses_ac/(double)n_tlb_evicts) << endl )
//	
//	PRINT_STATS( "First touch correct: " << first_touch_correct << endl )
//	PRINT_STATS( "First touch correct rate: " << (100.0 * ((double)first_touch_correct / (double)page_table.size())) << '%' << endl )

//	analyze_pgtb_threads(stats_file);
//	analyze_pgtb_nodes(stats_file);

	cout << "printing page table..." << endl;
	print_pgtb();
	
	PRINT_STATS( "DBA time: " << diff_time << 's' << endl )
	
	stats_file.close();
}

static int pintid_to_ktid[MAX_THREADS];
static int pintid_to_appid[MAX_THREADS];
static int appid_to_pintid[MAX_THREADS];
static int ktids[MAX_THREADS];

static VOID memaccess(BOOL is_Read, ADDRINT pc, ADDRINT addr, INT32 size, THREADID threadid)
{
	pte_t *tentry;

	assert(threadid < MAX_THREADS);
	threadid = pintid_to_appid[threadid];
	assert(threadid < MAX_THREADS);
	
	addr = addr & page_mask;
	
	tentry = page_table.fetch(addr, threadid);
	if (!tentry) {
		hash_fail++;
		return;
	}

	tentry->thread[threadid].naccess++;
}

VOID trace_memory(INS ins, VOID *v)
{
	if (INS_IsMemoryRead(ins)) {
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)memaccess, IARG_BOOL, true, IARG_INST_PTR, IARG_MEMORYREAD_EA, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
	}
	if (INS_HasMemoryRead2(ins)) {
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)memaccess, IARG_BOOL, true, IARG_INST_PTR, IARG_MEMORYREAD2_EA, IARG_MEMORYREAD_SIZE, IARG_THREAD_ID, IARG_END);
	}
	if (INS_IsMemoryWrite(ins)) {
		INS_InsertCall( ins, IPOINT_BEFORE, (AFUNPTR)memaccess, IARG_BOOL, false, IARG_INST_PTR, IARG_MEMORYWRITE_EA, IARG_MEMORYWRITE_SIZE, IARG_THREAD_ID, IARG_END);
	}
}

/*static void print_tmap (int n)
{
	int i;
	
	cerr << endl << endl;
	
	for (i=0; i<MAX_THREADS; i++) {
		if (appid_to_pintid[i] != -1) {
			cerr << "appTid " << i << " pinID " << appid_to_pintid[i] << " OS id " << pintid_to_ktid[appid_to_pintid[i]] << endl;
		}
	}
}*/

VOID ThreadStart(THREADID threadid, CONTEXT *ctxt, INT32 flags, VOID *v)
{
	OS_THREAD_ID tid;
	int i, appid;
	FILE *fp;
	char fname[100];
	

	tid = PIN_GetTid();

	PIN_GetLock(&init_lock, threadid+1);

	i = __sync_fetch_and_add(&numThreads, 1); // i know we are already locked, but there are other places where we read this var
	
	assert(numThreads <= MAX_THREADS);

	if (startTsc == 0){
		startTsc = getTSC();
	}
	
	pintid_to_ktid[threadid] = tid;
	ktids[i] = tid;
	
	sprintf(fname, "/proc/track-processes/%i", tid);
	fp = fopen(fname, "r");
	if (!fp) {
		cout << "error opening " << fname << endl;
		exit(1);
	}
	if(!fscanf(fp, "%i", &appid))
		cerr << "error" << endl;

	fclose(fp);
	
	pintid_to_appid[threadid] = appid;
	appid_to_pintid[appid] = threadid;

	PIN_ReleaseLock(&init_lock);
	
	cerr << "Thread " << threadid << " OS id " << tid << " app id " << appid << " registered" << endl;
}

VOID ThreadFini(THREADID threadid, const CONTEXT *ctxt, INT32 code, VOID *v)
{
	cerr << "Thread " << threadid << " finished" << endl;
}

int main(int argc, char *argv[])
{
	int i;
	char *env;
	char hostname[HOST_NAME_MAX + 1], hostdate[1024]; 
	struct stat st = {0};
	time_t t;

	time(&t);
	strftime(hostdate, 1023, "%d.%m.%Y.%H.%M.%S", localtime(&t));
	gethostname(hostname, HOST_NAME_MAX);
	sprintf(addr_fname, "output/addr.%s.%s.csv", hostname, hostdate);
	sprintf(stat_fname, "output/stat.%s.%s.txt", hostname, hostdate);

	if(stat("output", &st) == -1)
    	if(mkdir("output", 0700) == -1){
    		fprintf(stderr, "error creating output directory\n");
			exit(EXIT_FAILURE);
    	}	
	
	if (PIN_Init(argc,argv)) {
		printf("pintool error\n");
		return 1;
	}
	
	assert(sizeof(void*) == sizeof(unsigned long));

	PIN_InitSymbols();

	PIN_InitLock(&init_lock);
	
	PIN_AddThreadStartFunction(ThreadStart, 0);
	PIN_AddThreadFiniFunction(ThreadFini, 0);

	INS_AddInstrumentFunction(trace_memory, 0);
	
	PIN_AddFiniFunction(Fini, 0);
	
	#define ENV_CFG_INT(envname, target) \
		env = getenv(envname); \
		if (env) { \
			target = atoi(env); \
			cout << "env " << envname << " set to " << target << endl;\
		} \
		else { \
			cout << "Undefined env " << envname << " using default value " << target << endl; \
		}
	
	#define ENV_CFG_INT64(envname, target) \
		env = getenv(envname); \
		if (env && !(env[0] == 0 || (env[0] == '0' && env[1] == 0))) { \
			sscanf(env, "%llu", &target);\
			cout << "env " << envname << " set to " << target << endl;\
		} \
		else { \
			cout << "Undefined env " << envname << " using default value " << target << endl; \
		}
	
	ENV_CFG_INT(envname_page_size, page_size)
	ENV_CFG_INT(envname_numa_nodes, numa_nodes)
	
	page_size_bits = get_n_bits(page_size);

	page_mask = 0;
	for (i=0; i< (int)page_size_bits; i++) {
		page_mask |= (1 << i);
	}
	page_mask = ~page_mask;

	cout << "MAX_THREADS: " << MAX_THREADS << endl;
	cout << "Page size: " << page_size << endl;
	cout << "Page size bits: " << page_size_bits << endl;

	gettimeofday(&timer_start, NULL);

	PIN_StartProgram();

	return 0;
}