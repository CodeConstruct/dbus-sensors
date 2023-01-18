
#pragma once

#include "NVMeIntf.hpp"

#include <boost/asio.hpp>
#include <sdbusplus/asio/connection.hpp>
#include <sdbusplus/asio/object_server.hpp>
#include <xyz/openbmc_project/Inventory/Item/StorageController/server.hpp>
#include <xyz/openbmc_project/NVMe/NVMeAdmin/server.hpp>

#include <utility>

class NVMeControllerPlugin;
class NVMeController :
    private sdbusplus::xyz::openbmc_project::Inventory::Item::server::
        StorageController,
    private sdbusplus::xyz::openbmc_project::NVMe::server::NVMeAdmin,
    public std::enable_shared_from_this<NVMeController>

{
  public:
    static std::shared_ptr<NVMeController> create(
        boost::asio::io_context& io, sdbusplus::asio::object_server& objServer,
        std::shared_ptr<sdbusplus::asio::connection> conn, std::string path,
        std::shared_ptr<NVMeMiIntf> nvmeIntf, nvme_mi_ctrl_t ctrl);

    ~NVMeController() override;

    void start(std::shared_ptr<NVMeControllerPlugin> nvmePlugin);

    // setup association to the secondary controllers. Clear the Association if
    // empty.
    void setSecAssoc(
        const std::vector<std::shared_ptr<NVMeController>> secCntrls);

    inline void setSecAssoc()
    {
        setSecAssoc({});
    }

    /**
     * @brief Get cntrl_id for the binded NVMe controller
     *
     * @return cntrl_id
     */
    uint16_t getCntrlId() const
    {
        return *reinterpret_cast<uint16_t*>(
            (reinterpret_cast<uint8_t*>(nvmeCtrl) +
             std::max(sizeof(uint16_t), sizeof(void*))));
    }

  private:
    friend class NVMeControllerPlugin;

    boost::asio::io_context& io;
    sdbusplus::asio::object_server& objServer;
    std::shared_ptr<sdbusplus::asio::connection> conn;
    std::string path;

    std::shared_ptr<sdbusplus::asio::dbus_interface> securityInterface;

    std::shared_ptr<NVMeMiIntf> nvmeIntf;
    nvme_mi_ctrl_t nvmeCtrl;

    // The Association interface to secondary controllers from a primary
    // controller
    std::shared_ptr<sdbusplus::asio::dbus_interface> secAssoc;

    // NVMe Plug-in for vendor defined command/field
    std::weak_ptr<NVMeControllerPlugin> plugin;

    NVMeController(boost::asio::io_context& io,
                   sdbusplus::asio::object_server& objServer,
                   std::shared_ptr<sdbusplus::asio::connection> conn,
                   std::string path, std::shared_ptr<NVMeMiIntf> nvmeIntf,
                   nvme_mi_ctrl_t ctrl);
    void init();

    static void checkLibNVMeError(int status, int saved_errno,
                                  const char* method_name);

    /* NVMeAdmin method overload */

    /** @brief Implementation for GetLogPage
     *  Send GetLogPage command to NVMe device
     *
     *  @param[in] lid - Log Page Identifier
     *  @param[in] nsid - Namespace Identifier
     *  @param[in] lsp - Log Specific Field
     *  @param[in] lsi - Log Specific Identifier
     *
     *  @return log[sdbusplus::message::unix_fd] - Returned Log Page
     */
    sdbusplus::message::unix_fd getLogPage(uint8_t lid, uint32_t nsid,
                                           uint8_t lsp, uint16_t lsi) override;

    /** @brief Implementation for Identify
     *  Send Identify command to NVMe device
     *
     *  @param[in] cns - Controller or Namespace Structure
     *  @param[in] nsid - Namespace Identifier
     *  @param[in] cntid - Controller Identifier
     *
     *  @return data[sdbusplus::message::unix_fd] - Identify Data
     */
    sdbusplus::message::unix_fd identify(uint8_t cns, uint32_t nsid,
                                         uint16_t cntid) override;
    /** Set value of FirmwareCommitStatus
     * Used to reset the the status back to ready if the commit is not in
     * process.
     */
    NVMeAdmin::FwCommitStatus
        firmwareCommitStatus(NVMeAdmin::FwCommitStatus) override;

    /** @brief Implementation for FirmwareCommitAsync
     *  Send Firmware Commit command to NVMe device
     *
     *  @param[in] commitAction - Commit Action defined by NVMe base spec
     * (Figure 175 of rev 1.4)
     *  @param[in] firmwareSlot - Firmware Slot
     *  @param[in] bpid - Boot Partition ID
     */
    void firmwareCommitAsync(uint8_t commitAction, uint8_t firmwareSlot,
                             bool bpid) override;

    void securitySendMethod(boost::asio::yield_context yield, uint8_t proto,
                            uint16_t proto_specific, std::span<uint8_t> data);

    std::vector<uint8_t> securityReceiveMethod(boost::asio::yield_context yield,
                                               uint8_t proto,
                                               uint16_t proto_specific,
                                               uint32_t transfer_length);
};
