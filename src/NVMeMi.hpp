#include "NVMeIntf.hpp"
#include "Utils.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/bus.hpp>

#include <thread>

// A worker thread for calling NVMeMI cmd.
class NVMeMiWorker
{
  private:
    bool workerStop;
    std::mutex workerMtx;
    std::condition_variable workerCv;
    boost::asio::io_context workerIO;
    bool workerIsNotified = false;
    std::thread thread;

  public:
    NVMeMiWorker();
    NVMeMiWorker(const NVMeMiWorker&) = delete;
    ~NVMeMiWorker();
    void post(std::function<void(void)>&& func);
};

class NVMeMi : public NVMeMiIntf, public std::enable_shared_from_this<NVMeMi>
{
  public:
    NVMeMi(boost::asio::io_context& io,
           const std::shared_ptr<sdbusplus::asio::connection>& conn,
           const std::shared_ptr<const MctpDevice>& device,
           const std::shared_ptr<NVMeMiWorker>& worker,
           PowerState readState = PowerState::always);
    ~NVMeMi() override;

    bool flushOperations(std::function<void()>&& cb) override;
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
                         std::function<void(const std::error_code&,
                                            nvme_status_field)>&& cb) override;

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

    void adminAttachDetachNamespace(
        nvme_mi_ctrl_t ctrl, uint16_t ctrlid, uint32_t nsid, bool attach,
        std::function<void(const std::error_code&, int nvme_status)>&& cb)
        override;

    void adminSanitize(nvme_mi_ctrl_t ctrl, enum nvme_sanitize_sanact sanact,
                       uint8_t passes, uint32_t pattern, bool invert_pattern,
                       std::function<void(nvme_ex_ptr ex)>&& cb) override;

    void start(const std::shared_ptr<MctpEndpoint>& ep) override;
    void stop() override;
    void recover() override;

  private:
    // the transfer size for nvme mi messages.
    // define in github.com/linux-nvme/libnvme/blob/master/src/nvme/mi.c
    static constexpr size_t nvme_mi_xfer_size = 4096;

    static nvme_root_t nvmeRoot;

    boost::asio::io_context& io;
    std::shared_ptr<const MctpDevice> device;

    // power state
    std::unique_ptr<PowerCallbackEntry> powerCallback;
    PowerState readState;

    /*
     * A state machine to represent the current status of the MCTP connection.
     * In Reset state, the MCTP endpoint (EP) is not setup with the device.
     * In event of successful setup we move from Reset to Configured. If
     * opening the EP is successful from Configured the status will change to
     * Initiated. The status will change to Connected once the MTU of local
     * and device side MTU and frequency is optimized. In an event of connection
     * EP closure, the status will move back to Reset via Terminating.
     *
     * Transitions to the terminal state indicate a logic error.
     *
     * stateDiagram
     *   [*] --> Reset
     *
     *   Reset --> Reset: epReset()
     *   Reset --> [*]: epConnect()
     *   Reset --> [*]: epOptimize()
     *
     *   Initiated --> Terminating: epReset()
     *   Initiated --> Initiated: epConnect()
     *   Initiated --> Connected: epOptimize()
     *
     *   Connected --> Terminating: epReset()
     *   Connected --> Connected: epConnect()
     *   Connected --> Connected: epOptimize()
     *
     *   Terminating --> Reset: Reset close job executes
     *   Terminating --> Terminating: epReset()
     *   Terminating --> Terminating: epConnect()
     *   Terminating --> [*]: epOptimize()
     */
    enum class Status
    {
        Reset,
        Initiated,
        Connected,
        Terminating,
    };

    void epReset();
    bool epConnect(int lnid, uint8_t leid);
    void epOptimize();

    Status mctpStatus;
    std::shared_ptr<MctpEndpoint> endpoint;
    uint16_t mtu;
    nvme_mi_ep_t nvmeEP;
    // Handle a start() while in Status::Terminating on entry to Status::Reset.
    bool restart;
    bool startLoopRunning;

    std::shared_ptr<NVMeMiWorker> worker;
    void post(std::function<void(void)>&& func);

    void
        miConfigureRemoteMCTP(uint8_t port, uint16_t mtu,
                              uint8_t max_supported_freq,
                              std::function<void(const std::error_code&)>&& cb);

    void miConfigureSMBusFrequency(
        uint8_t port_id, uint8_t max_supported_freq,
        std::function<void(const std::error_code&)>&& cb);

    void miSetMCTPConfiguration(
        std::function<void(const std::error_code&)>&& cb);

    void configureLocalRouteMtu(
        std::function<void(const std::error_code& ec)>&& completed,
        int retries = 5);

    std::optional<std::error_code> isEndpointDegraded() const;

    bool readingStateGood() const
    {
        return ::readingStateGood(readState);
    }

    std::error_code try_post(std::function<void(void)>&& func);

    void adminFwDownloadChunk(
        nvme_mi_ctrl_t ctrl, std::string firmwarefile, size_t size,
        size_t offset, int attempt_count,
        std::function<void(const std::error_code&, nvme_status_field)>&& cb);

    void getTelemetryLogChunk(
        nvme_mi_ctrl_t ctrl, bool host, uint64_t offset,
        std::vector<uint8_t>&& data,
        std::function<void(const std::error_code&, std::span<uint8_t>)>&& cb);

    size_t getBlockSize(nvme_mi_ctrl_t ctrl, size_t lba_format);
};
