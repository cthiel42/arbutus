#ifndef __MEMLEAK_H
#define __MEMLEAK_H

#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240

struct alloc_info {
	__u64 size;
	__u64 timestamp_ns;
	int stack_id;
	__u32 pid;
	char comm[16];  // process name
};

union combined_alloc_info {
	struct {
		__u64 total_size : 40;
		__u64 number_of_allocs : 24;
	} fields;
	__u64 bits;
};

#endif /* __MEMLEAK_H */
