#pragma once
#include <libnvme-mi.h>

#include <functional>
#include <memory>
#include <span>

class NVMeIntf
{
  public:
    NVMeIntf() = default;
    virtual ~NVMeIntf() = default;
};

// Interface to get information via NVMe MI Basic CMD protocol.
class NVMeBasicIntf : public NVMeIntf
{
  public:
    struct DriveStatus
    {
        uint8_t SmartWarnings;
        uint8_t Temp;
        uint8_t DriveLifeUsed;
        uint8_t WarningTemp;
        uint8_t PowerState;
    };

    enum StatusFlags : uint8_t
    {
        NVME_MI_BASIC_SFLGS_DRIVE_NOT_READY = 0x40,
        NVME_MI_BASIC_SFLGS_DRIVE_FUNCTIONAL = 0x20,
    };

    NVMeBasicIntf() = default;

    // The i2c bus number
    virtual int getBus() const = 0;
    // The i2c address for NVMe Basic
    virtual int getAddr() const = 0;

    // Get NVMe drive status, data address is from 00h~07h
    virtual void getStatus(
        std::function<void(const std::error_code&, DriveStatus*)>&& cb) = 0;

    ~NVMeBasicIntf() override = default;
};

class NVMeMiIntf : public NVMeIntf
{
  public:
    virtual int getNID() const = 0;
    virtual int getEID() const = 0;
    virtual void miSubsystemHealthStatusPoll(
        std::function<void(const std::error_code&,
                           nvme_mi_nvm_ss_health_status*)>&& cb) = 0;
    virtual void
        miScanCtrl(std::function<void(const std::error_code&,
                                      const std::vector<nvme_mi_ctrl_t>&)>
                       cb) = 0;
    virtual void adminIdentify(
        nvme_mi_ctrl_t ctrl, nvme_identify_cns cns, uint32_t nsid,
        uint16_t cntid,
        std::function<void(const std::error_code&, std::span<uint8_t>)>&&
            cb) = 0;
    virtual void adminGetLogPage(
        nvme_mi_ctrl_t ctrl, nvme_cmd_get_log_lid lid, uint32_t nsid,
        uint8_t lsp, uint16_t lsi,
        std::function<void(const std::error_code&, std::span<uint8_t>)>&&
            cb) = 0;

    /**
     * adminXfer() -  Raw admin transfer interface.
     * @ctrl: controller to send the admin command to
     * @admin_req: request header
     * @data: request data payload
     * @resp_data_offset: offset into request data to retrieve from controller
     * @cb: callback function after the response received.
     * @ec: error code
     * @admin_resp: response header
     * @resp_data: response data payload
     *
     * Performs an arbitrary NVMe Admin command, using the provided request
     * header, in @admin_req. The requested data is attached by @data, if any.
     *
     * On success, @cb will be called and response header and data are stored in
     * @admin_resp and @resp_data, which has an optional appended payload
     * buffer. The response data does not include the Admin request header, so 0
     * represents no payload.
     *
     * As with all Admin commands, we can request partial data from the Admin
     * Response payload, offset by @resp_data_offset. In case of resp_data
     * contains only partial data of the caller's requirement, a follow-up call
     * to adminXfer with offset is required.
     *
     * See: &struct nvme_mi_admin_req_hdr and &struct nvme_mi_admin_resp_hdr.
     *
     * @ec will be returned on failure.
     */
    virtual void
        adminXfer(nvme_mi_ctrl_t ctrl, const nvme_mi_admin_req_hdr& admin_req,
                  std::span<uint8_t> data,
                  std::function<void(const std::error_code& ec,
                                     const nvme_mi_admin_resp_hdr& admin_resp,
                                     std::span<uint8_t> resp_data)>&& cb) = 0;
};