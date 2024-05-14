#include <libnvme-mi.h>

#include <gmock/gmock.h>

// libnvme mock implementation

#define DS_UNUSED __attribute__((unused))

const char* nvme_status_to_string(int status DS_UNUSED, bool fabrics DS_UNUSED)
{
    return "Unimplemented";
}

void nvme_init_ctrl_list(struct nvme_ctrl_list* cntlist DS_UNUSED,
                         __u16 num_ctrls DS_UNUSED, __u16* ctrlist DS_UNUSED)
{}
