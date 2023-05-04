#include "NVMeIntf.hpp"
#include "Utils.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/bus.hpp>

#include <thread>

class NVMeMi : public NVMeMiIntf, public std::enable_shared_from_this<NVMeMi>
{
  public:
    NVMeMi(boost::asio::io_context& io, std::shared_ptr<sdbusplus::asio::connection> conn, int bus,
           int addr, bool singleThreadMode = false,
           PowerState readState = PowerState::always);
    ~NVMeMi() override;

    int getNID() const override
    {
        return nid;
    }
    int getEID() const override
    {
        return eid;
    }
    void miSubsystemHealthStatusPoll(
        std::function<void(const std::error_code&,
                           nvme_mi_nvm_ss_health_status*)>&& cb) override;
    void miScanCtrl(std::function<void(const std::error_code&,
                                       const std::vector<nvme_mi_ctrl_t>&)>
                        cb) override;
    void adminIdentify(
        nvme_mi_ctrl_t ctrl, nvme_identify_cns cns, uint32_t nsid,
        uint16_t cntid,
        std::function<void(nvme_ex_ptr, std::span<uint8_t>)>&& cb) override;
    void adminGetLogPage(nvme_mi_ctrl_t ctrl, nvme_cmd_get_log_lid lid,
                         uint32_t nsid, uint8_t lsp, uint16_t lsi,
                         std::function<void(const std::error_code&,
                                            std::span<uint8_t>)>&& cb) override;

    void adminFwCommit(
        nvme_mi_ctrl_t ctrl, nvme_fw_commit_ca action, uint8_t slot, bool bpid,
        std::function<void(const std::error_code&, nvme_status_field)>&& cb)
        override;

    void adminFwDownload(nvme_mi_ctrl_t ctrl, std::string firmwarefile,
        std::function<void(const std::error_code&, nvme_status_field)>&& cb)
        override;

    void adminXfer(nvme_mi_ctrl_t ctrl, const nvme_mi_admin_req_hdr& admin_req,
                   std::span<uint8_t> data, unsigned int timeout_ms,
                   std::function<void(const std::error_code&,
                                      const nvme_mi_admin_resp_hdr&,
                                      std::span<uint8_t>)>&& cb) override;

    void adminSecuritySend(nvme_mi_ctrl_t ctrl, uint8_t proto,
                           uint16_t proto_specific, std::span<uint8_t> data,
                           std::function<void(const std::error_code&,
                                              int nvme_status)>&& cb) override;

    void adminSecurityReceive(
        nvme_mi_ctrl_t ctrl, uint8_t proto, uint16_t proto_specific,
        uint32_t transfer_length,
        std::function<void(const std::error_code&, int nvme_status,
                           std::span<uint8_t> data)>&& cb) override;

    void adminNonDataCmd(
        nvme_mi_ctrl_t ctrl, uint8_t opcode, uint32_t cdw1, uint32_t cdw2,
        uint32_t cdw3, uint32_t cdw10, uint32_t cdw11, uint32_t cdw12,
        uint32_t cdw13, uint32_t cdw14, uint32_t cdw15,
        std::function<void(const std::error_code&, int nvme_status,
                           uint32_t comption_dw0)>&& cb);

    void createNamespace(
        nvme_mi_ctrl_t ctrl, uint64_t size, size_t lba_format,
        bool metadata_at_end,
        std::function<void(nvme_ex_ptr ex)>&& submitted_cb,
        std::function<void(nvme_ex_ptr ex, NVMeNSIdentify newid)>&& finished_cb)
        override;

    void adminDeleteNamespace(
        nvme_mi_ctrl_t ctrl, uint32_t nsid,
        std::function<void(const std::error_code&, int nvme_status)>&& cb)
        override;

    void adminListNamespaces(
        nvme_mi_ctrl_t ctrl,
        std::function<void(nvme_ex_ptr ex, std::vector<uint32_t> ns)>&& cb)
        override;

  private:
    // the transfer size for nvme mi messages.
    // define in github.com/linux-nvme/libnvme/blob/master/src/nvme/mi.c
    static constexpr size_t nvme_mi_xfer_size = 4096;

    static nvme_root_t nvmeRoot;

    boost::asio::io_context& io;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    sdbusplus::bus_t& dbus;

    // I2C info
    int bus;
    int addr;

    // power state
    std::unique_ptr<PowerCallbackEntry> powerCallback;
    PowerState readState;

    // mctp connection
    nvme_mi_ep_t nvmeEP;

    int nid;
    uint8_t eid;
    std::string mctpPath;

    std::mutex mctpMtx;

    // A worker thread for calling NVMeMI cmd.
    class Worker
    {
      private:
        bool workerStop;
        std::mutex workerMtx;
        std::condition_variable workerCv;
        boost::asio::io_context workerIO;
        std::thread thread;

      public:
        Worker();
        Worker(const Worker&) = delete;
        ~Worker();
        void post(std::function<void(void)>&& func);
    };

    // A map from root bus number to the Worker
    // This map means to reuse the same worker for all NVMe EP under the same
    // I2C root bus. There is no real physical concurrency among the i2c/mctp
    // devices on the same bus. Though mctp kernel drive can schedule and
    // sequencialize the transactions but assigning individual worker thread to
    // each EP makes no sense.
    static std::map<int, std::weak_ptr<Worker>> workerMap;

    std::shared_ptr<Worker> worker;
    void post(std::function<void(void)>&& func);

    void initMCTP();

    void closeMCTP();

    bool isMCTPconnect() const;

    bool readingStateGood() const
    {
        return isMCTPconnect() && ::readingStateGood(readState);
    }

    std::error_code try_post(std::function<void(void)>&& func);

    void adminFwDownloadChunk(nvme_mi_ctrl_t ctrl, std::string firmwarefile, size_t size,
                              size_t offset, int attempt_count,
                              std::function<void(const std::error_code&, nvme_status_field)>&& cb);

    void getTelemetryLogChuck(
        nvme_mi_ctrl_t ctrl, bool host, uint64_t offset,
        std::vector<uint8_t>&& data,
        std::function<void(const std::error_code&, std::span<uint8_t>)>&& cb);

    size_t getBlockSize(nvme_mi_ctrl_t ctrl, size_t lba_format);
};
