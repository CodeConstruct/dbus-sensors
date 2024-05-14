#include <libnvme-mi.h>

#include <gmock/gmock.h>

// libnvme-mi mock implementation

#define DS_UNUSED __attribute__((unused))

extern "C"
{
struct nvme_mi_ctrl
{
    int member;
};

struct nvme_mi_ep
{
    struct nvme_mi_ctrl ctrl;
};

struct nvme_root
{
    struct nvme_mi_ep ep;
};
}

static struct nvme_root root;

const char* nvme_mi_status_to_string(int status DS_UNUSED)
{
    return "Unimplemented";
}

int nvme_mi_ep_set_timeout(nvme_mi_ep_t ep DS_UNUSED,
                           unsigned int timeout_ms DS_UNUSED)
{
    return 0;
}

unsigned int nvme_mi_ep_get_timeout(nvme_mi_ep_t ep DS_UNUSED)
{
    return 0;
}

nvme_root_t nvme_mi_create_root(FILE* fp DS_UNUSED, int log_level DS_UNUSED)
{
    return &root;
}

int nvme_mi_admin_sanitize_nvm(nvme_mi_ctrl_t ctrl DS_UNUSED,
                               struct nvme_sanitize_nvm_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_ns_attach(nvme_mi_ctrl_t ctrl DS_UNUSED,
                            struct nvme_ns_attach_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_admin_passthru(
    nvme_mi_ctrl_t ctrl DS_UNUSED, __u8 opcode DS_UNUSED, __u8 flags DS_UNUSED,
    __u16 rsvd DS_UNUSED, __u32 nsid DS_UNUSED, __u32 cdw2 DS_UNUSED,
    __u32 cdw3 DS_UNUSED, __u32 cdw10 DS_UNUSED, __u32 cdw11 DS_UNUSED,
    __u32 cdw12 DS_UNUSED, __u32 cdw13 DS_UNUSED, __u32 cdw14 DS_UNUSED,
    __u32 cdw15 DS_UNUSED, __u32 data_len DS_UNUSED, void* data DS_UNUSED,
    __u32 metadata_len DS_UNUSED, void* metadata DS_UNUSED,
    __u32 timeout_ms DS_UNUSED, __u32* result DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_security_send(nvme_mi_ctrl_t ctrl DS_UNUSED,
                                struct nvme_security_send_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_security_recv(nvme_mi_ctrl_t ctrl DS_UNUSED,
                                struct nvme_security_receive_args* args
                                    DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_fw_download(nvme_mi_ctrl_t ctrl DS_UNUSED,
                              struct nvme_fw_download_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_fw_commit(nvme_mi_ctrl_t ctrl DS_UNUSED,
                            struct nvme_fw_commit_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_xfer(nvme_mi_ctrl_t ctrl DS_UNUSED,
                       struct nvme_mi_admin_req_hdr* admin_req DS_UNUSED,
                       size_t req_data_size DS_UNUSED,
                       struct nvme_mi_admin_resp_hdr* admin_resp DS_UNUSED,
                       off_t resp_data_offset DS_UNUSED,
                       size_t* resp_data_size DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_identify_partial(nvme_mi_ctrl_t ctrl DS_UNUSED,
                                   struct nvme_identify_args* args DS_UNUSED,
                                   off_t offset DS_UNUSED,
                                   size_t size DS_UNUSED)
{
    return 0;
}

nvme_mi_ctrl_t nvme_mi_next_ctrl(nvme_mi_ep_t ep DS_UNUSED,
                                 nvme_mi_ctrl_t c DS_UNUSED)
{
    return nullptr;
}

nvme_mi_ctrl_t nvme_mi_first_ctrl(nvme_mi_ep_t ep DS_UNUSED)
{
    return nullptr;
}

int nvme_mi_scan_ep(nvme_mi_ep_t ep DS_UNUSED, bool force_rescan DS_UNUSED)
{
    return 0;
}

int nvme_mi_mi_subsystem_health_status_poll(
    nvme_mi_ep_t ep DS_UNUSED, bool clear DS_UNUSED,
    struct nvme_mi_nvm_ss_health_status* nshds DS_UNUSED)
{
    return 0;
}

int nvme_mi_mi_read_mi_data_port(nvme_mi_ep_t ep DS_UNUSED,
                                 __u8 portid DS_UNUSED,
                                 struct nvme_mi_read_port_info* p DS_UNUSED)
{
    return 0;
}

int nvme_mi_mi_read_mi_data_subsys(nvme_mi_ep_t ep DS_UNUSED,
                                   struct nvme_mi_read_nvm_ss_info* s DS_UNUSED)
{
    return -1;
}

void nvme_mi_close(nvme_mi_ep_t ep DS_UNUSED) {}

nvme_mi_ep_t nvme_mi_open_mctp(nvme_root_t root DS_UNUSED,
                               unsigned int netid DS_UNUSED,
                               uint8_t eid DS_UNUSED)
{
    return &root->ep;
}

int nvme_mi_admin_ns_mgmt(nvme_mi_ctrl_t ctrl DS_UNUSED,
                          struct nvme_ns_mgmt_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_admin_get_log(nvme_mi_ctrl_t ctrl DS_UNUSED,
                          struct nvme_get_log_args* args DS_UNUSED)
{
    return 0;
}

int nvme_mi_mi_config_set(nvme_mi_ep_t ep DS_UNUSED, __u32 dw0 DS_UNUSED,
                          __u32 dw1 DS_UNUSED)
{
    return 0;
}

int nvme_mi_mi_config_get(nvme_mi_ep_t ep DS_UNUSED, __u32 dw0 DS_UNUSED,
                          __u32 dw1 DS_UNUSED, __u32* nmresp DS_UNUSED)
{
    return 0;
}
