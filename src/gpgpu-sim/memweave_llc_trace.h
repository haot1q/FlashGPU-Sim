// MemWeave's optional observation of successful L2-to-DRAM queue enqueues.
// This is not a memory-controller acceptance or DRAM-command trace.
#ifndef MEMWEAVE_LLC_TRACE_H
#define MEMWEAVE_LLC_TRACE_H

#include <stdint.h>

class mem_fetch;

namespace memweave_llc_trace {

// Initializes once from MEMWEAVE_LLC_TRACE and writes a header even for an empty
// run. Unset means disabled. The current driver must synchronize before exit:
// the single simulator worker writes events, and shutdown only closes the file.
void initialize();
void observe_queue_full();
void record_enqueue(mem_fetch *request, unsigned subpartition, uint64_t cycle,
                    bool bypass);

}  // namespace memweave_llc_trace

#endif
